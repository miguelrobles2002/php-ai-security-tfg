"""
Advanced PHP Static Analyzer with Taint Tracking Engine
========================================================

Output contract (matches index.html → mostrarVulnerabilidades):
  Each finding dict contains:
    tipo          – vulnerability name (str)
    linea         – line number (int)
    severidad     – "Crítica" | "Alta" | "Media" | "Baja"
    cwe           – "CWE-89" etc.
    owasp         – "A03:2021" etc.
    confianza     – "87%" etc.
    descripcion   – what the vulnerability is (plain text, shown in ¿Qué es?)
    impacto       – what an attacker can do (shown in Impacto)
    solucion      – how to fix it (shown in Cómo solucionarlo)
    ejemplo_seguro– safe code snippet (shown in Ejemplo seguro, <pre> block)
    codigo        – the vulnerable source line (shown in Código afectado)
    cadena_taint  – propagation chain list (internal, not rendered)
    sink          – matched sink text (internal)
"""

from __future__ import annotations

import re
from collections import defaultdict
from dataclasses import dataclass, field
from typing import ClassVar, Dict, FrozenSet, List, Optional, Set, Tuple


# ===========================================================================
# 1. Taint Engine
# ===========================================================================

class TaintEngine:
    SOURCE_PATTERN = re.compile(
        r"\$_(?:GET|POST|REQUEST|COOKIE|FILES|SERVER|ENV)\s*\[",
        re.IGNORECASE,
    )
    ASSIGN_PATTERN = re.compile(
        r"(\$\w+)\s*\.?=\s*(.+?)(?:;|$)",
        re.IGNORECASE,
    )
    SANITIZERS: ClassVar[Set[str]] = {
        "htmlspecialchars", "htmlentities", "esc_html", "esc_attr",
        "wp_kses", "strip_tags",
        "intval", "floatval", "abs", "round",
        "mysqli_real_escape_string", "mysql_real_escape_string", "addslashes",
        "escapeshellarg", "escapeshellcmd",
        "realpath", "basename",
        "filter_input", "filter_var",
    }

    def __init__(self) -> None:
        self._tainted: Dict[str, TaintInfo] = {}

    def process_line(self, line: str, lineno: int) -> "TaintState":
        # Direct source: $x = $_GET['foo']
        if self.SOURCE_PATTERN.search(line):
            assign = self.ASSIGN_PATTERN.search(line)
            if assign:
                var = assign.group(1)
                self._set_taint(var, lineno, line.strip(), 1.0)

        # Propagation: $y = func($x) or $y = $x . "str"
        assign = self.ASSIGN_PATTERN.search(line)
        if assign:
            lhs, rhs = assign.group(1), assign.group(2)
            tainted_in_rhs = [
                (v, info) for v, info in self._tainted.items()
                if re.search(re.escape(v) + r"\b", rhs)
            ]
            if tainted_in_rhs:
                sanitized = any(
                    re.search(rf"\b{s}\s*\(", rhs, re.IGNORECASE)
                    for s in self.SANITIZERS
                )
                if not sanitized:
                    best_var, best_info = max(tainted_in_rhs, key=lambda t: t[1].strength)
                    self._tainted[lhs] = TaintInfo(
                        var_name=lhs,
                        introduced_at=best_info.introduced_at,
                        propagated_at=lineno,
                        chain=best_info.chain + [f"línea {lineno}: {lhs} ← {best_var}"],
                        strength=best_info.strength * 0.95,
                        origin_source=best_info.origin_source,
                    )
                else:
                    self._tainted.pop(lhs, None)

        return TaintState(dict(self._tainted), lineno)

    def _set_taint(self, var: str, lineno: int, source_line: str, strength: float) -> None:
        self._tainted[var] = TaintInfo(
            var_name=var,
            introduced_at=lineno,
            propagated_at=lineno,
            chain=[f"línea {lineno}: {var} ← entrada del usuario ({source_line[:60]})"],
            strength=strength,
            origin_source=source_line,
        )


@dataclass
class TaintInfo:
    var_name: str
    introduced_at: int
    propagated_at: int
    chain: List[str]
    strength: float
    origin_source: str


@dataclass
class TaintState:
    tainted: Dict[str, TaintInfo]
    line_no: int

    _SUPER_RE: ClassVar[re.Pattern] = re.compile(
        r"\$_(?:GET|POST|REQUEST|COOKIE|FILES|SERVER)\s*\[",
        re.IGNORECASE,
    )

    def any_tainted_in(self, text: str) -> Optional[TaintInfo]:
        for var, info in self.tainted.items():
            if re.search(re.escape(var) + r"\b", text):
                return info
        return None

    def superglobal_in(self, text: str) -> bool:
        return bool(self._SUPER_RE.search(text))


# ===========================================================================
# 2. Vulnerability Rules
# ===========================================================================

@dataclass
class VulnRule:
    vuln_type: str          # shown as `tipo`
    cwe_id: int
    cvss_base: float
    owasp: str
    severity: str           # internal: "CRITICAL"|"HIGH"|"MEDIUM"|"LOW"
    sinks: Tuple[re.Pattern, ...]
    sanitizers: Tuple[str, ...]
    direct_source_bonus: int
    propagated_bonus: int
    sanitizer_penalty: int
    prepared_stmt_penalty: int
    descripcion: str        # ¿Qué es? — plain explanation for the dev
    impacto: str            # Impacto — attacker capability
    solucion: str           # Cómo solucionarlo
    ejemplo_seguro: str     # safe PHP code snippet


# Severity label map → Spanish UI label
_SEV_ES: Dict[str, str] = {
    "CRITICAL": "Crítica",
    "HIGH":     "Alta",
    "MEDIUM":   "Media",
    "LOW":      "Baja",
}

VULN_RULES: List[VulnRule] = [

    VulnRule(
        vuln_type="SQL Injection",
        cwe_id=89, cvss_base=9.8, owasp="A03:2021", severity="CRITICAL",
        sinks=(
            re.compile(
                r"""(?:->|\b)(?:query|execute|real_query|multi_query|"""
                r"""mysql_query|mssql_query|pg_query|sqlite_query)\s*\(""",
                re.IGNORECASE,
            ),
            re.compile(
                r"""(?:SELECT|INSERT|UPDATE|DELETE|DROP|TRUNCATE)\s+.{0,80}\$""",
                re.IGNORECASE | re.DOTALL,
            ),
        ),
        sanitizers=(
            "prepare(", "bindParam(", "bindValue(", "bind_param(",
            "PDO::", "intval(", "FILTER_VALIDATE_INT",
            "mysqli_real_escape_string(", "mysql_real_escape_string(",
        ),
        direct_source_bonus=40, propagated_bonus=30,
        sanitizer_penalty=60, prepared_stmt_penalty=70,
        descripcion=(
            "La entrada del usuario se concatena directamente en una consulta SQL "
            "sin parametrizar. El atacante puede alterar la lógica de la consulta "
            "inyectando fragmentos SQL arbitrarios."
        ),
        impacto=(
            "Extracción completa de la base de datos, bypass de autenticación, "
            "modificación o eliminación de datos, y en algunos casos ejecución "
            "de comandos en el sistema operativo (xp_cmdshell, INTO OUTFILE…)."
        ),
        solucion=(
            "Usa sentencias preparadas con PDO o MySQLi. Nunca concatenes variables "
            "directamente en la cadena SQL. Si el valor debe ser entero, valídalo "
            "con intval() antes de usarlo."
        ),
        ejemplo_seguro=(
            "// PDO — sentencia preparada\n"
            "$stmt = $pdo->prepare('SELECT * FROM users WHERE id = :id');\n"
            "$stmt->bindParam(':id', $_GET['id'], PDO::PARAM_INT);\n"
            "$stmt->execute();\n\n"
            "// MySQLi\n"
            "$stmt = $mysqli->prepare('SELECT * FROM users WHERE id = ?');\n"
            "$stmt->bind_param('i', $_GET['id']);\n"
            "$stmt->execute();"
        ),
    ),

    VulnRule(
        vuln_type="XSS (Reflected)",
        cwe_id=79, cvss_base=6.1, owasp="A03:2021", severity="HIGH",
        sinks=(
            re.compile(r"""\becho\b""", re.IGNORECASE),
            re.compile(r"""\bprint\s*\(?""", re.IGNORECASE),
            re.compile(r"""<\?="""),
            re.compile(r"""\bprintf\s*\(""", re.IGNORECASE),
        ),
        sanitizers=(
            "htmlspecialchars(", "htmlentities(", "esc_html(", "esc_attr(",
            "wp_kses(", "strip_tags(",
        ),
        direct_source_bonus=45, propagated_bonus=35,
        sanitizer_penalty=75, prepared_stmt_penalty=0,
        descripcion=(
            "Un valor controlado por el usuario se envía al navegador sin codificación HTML. "
            "El navegador interpreta el contenido como HTML/JS, ejecutando código arbitrario "
            "en el contexto de la página."
        ),
        impacto=(
            "Robo de cookies de sesión, redirección a sitios maliciosos, "
            "defacement de la página, keylogging, y ataques de phishing "
            "disfrazados bajo el dominio legítimo."
        ),
        solucion=(
            "Codifica toda salida con htmlspecialchars($var, ENT_QUOTES, 'UTF-8') "
            "justo antes de imprimirla. Nunca confíes en que los datos ya estén "
            "limpios porque vienen de la base de datos."
        ),
        ejemplo_seguro=(
            "// Salida segura\n"
            "echo htmlspecialchars($_GET['nombre'], ENT_QUOTES, 'UTF-8');\n\n"
            "// En WordPress\n"
            "echo esc_html( get_query_var('s') );"
        ),
    ),

    VulnRule(
        vuln_type="Command Injection",
        cwe_id=78, cvss_base=9.8, owasp="A03:2021", severity="CRITICAL",
        sinks=(
            re.compile(
                r"""\b(?:system|exec|shell_exec|passthru|popen|proc_open|pcntl_exec)\s*\(""",
                re.IGNORECASE,
            ),
            re.compile(r"""`[^`]*\$"""),
        ),
        sanitizers=("escapeshellarg(", "escapeshellcmd("),
        direct_source_bonus=50, propagated_bonus=40,
        sanitizer_penalty=55, prepared_stmt_penalty=0,
        descripcion=(
            "Una función de ejecución de shell recibe como argumento datos "
            "controlados por el usuario sin sanear. El atacante puede encadenar "
            "comandos adicionales usando metacaracteres del shell (;, |, &&, $())."
        ),
        impacto=(
            "Ejecución remota de código (RCE) con los privilegios del proceso PHP. "
            "El atacante puede leer ficheros, crear backdoors, pivotar a la red "
            "interna o borrar datos."
        ),
        solucion=(
            "Envuelve siempre el argumento con escapeshellarg(). Mejor aún, "
            "evita llamar al shell: usa funciones PHP nativas (rename(), copy()…) "
            "o librerías que no pasen por el shell."
        ),
        ejemplo_seguro=(
            "// Mal\n"
            "system('convert ' . $_GET['file'] . ' output.png');\n\n"
            "// Bien\n"
            "$file = escapeshellarg($_GET['file']);\n"
            "system('convert ' . $file . ' output.png');\n\n"
            "// Mejor: sin shell\n"
            "// Usa la extensión Imagick directamente."
        ),
    ),

    VulnRule(
        vuln_type="File Inclusion (LFI/RFI)",
        cwe_id=98, cvss_base=9.8, owasp="A06:2021", severity="CRITICAL",
        sinks=(
            re.compile(
                r"""\b(?:include|require|include_once|require_once)\s*[\(\s][^;)]*\$""",
                re.IGNORECASE,
            ),
        ),
        sanitizers=("realpath(", "basename(", "in_array(", "whitelist"),
        direct_source_bonus=45, propagated_bonus=35,
        sanitizer_penalty=50, prepared_stmt_penalty=0,
        descripcion=(
            "La ruta del fichero a incluir se construye a partir de entrada del usuario. "
            "En LFI el atacante puede leer ficheros sensibles del servidor (/etc/passwd). "
            "En RFI puede inyectar un script remoto si allow_url_include está activo."
        ),
        impacto=(
            "Lectura de ficheros arbitrarios del sistema, ejecución de código PHP "
            "arbitrario (RFI), y escalada a RCE completo."
        ),
        solucion=(
            "Usa una lista blanca estática de nombres de fichero permitidos. "
            "Nunca compongas rutas de forma dinámica con input del usuario. "
            "Valida con realpath() que la ruta resultante está dentro del directorio esperado."
        ),
        ejemplo_seguro=(
            "$allowed = ['home', 'about', 'contact'];\n"
            "$page = $_GET['page'];\n"
            "if (!in_array($page, $allowed, true)) {\n"
            "    $page = 'home';\n"
            "}\n"
            "include __DIR__ . '/pages/' . $page . '.php';"
        ),
    ),

    VulnRule(
        vuln_type="Code Injection (eval)",
        cwe_id=95, cvss_base=10.0, owasp="A03:2021", severity="CRITICAL",
        sinks=(
            re.compile(r"""\beval\s*\(""", re.IGNORECASE),
            re.compile(r"""\bcreate_function\s*\(""", re.IGNORECASE),
            re.compile(r"""\bpreg_replace\s*\(.*['"]/e""", re.IGNORECASE),
        ),
        sanitizers=(),
        direct_source_bonus=55, propagated_bonus=45,
        sanitizer_penalty=10, prepared_stmt_penalty=0,
        descripcion=(
            "eval() o create_function() evalúan como código PHP una cadena que contiene "
            "datos del usuario. No existe forma segura de pasar input externo a eval()."
        ),
        impacto=(
            "Ejecución de código PHP arbitrario: RCE total, creación de webshells, "
            "exfiltración de datos, control completo del servidor."
        ),
        solucion=(
            "Elimina el uso de eval(). Reestructura la lógica usando arrays de callbacks, "
            "match/switch o patrones de diseño. Si necesitas ejecutar expresiones, "
            "usa una librería de sandboxing con gramática restringida."
        ),
        ejemplo_seguro=(
            "// Mal\n"
            "eval('$result = ' . $_GET['expr'] . ';');\n\n"
            "// Bien: mapea operaciones permitidas\n"
            "$ops = ['suma' => fn($a,$b) => $a+$b, 'resta' => fn($a,$b) => $a-$b];\n"
            "$op  = $_GET['op'] ?? '';\n"
            "if (isset($ops[$op])) {\n"
            "    $result = $ops[$op](intval($_GET['a']), intval($_GET['b']));\n"
            "}"
        ),
    ),

    VulnRule(
        vuln_type="Insecure Deserialization",
        cwe_id=502, cvss_base=9.8, owasp="A08:2021", severity="CRITICAL",
        sinks=(
            re.compile(r"""\bunserialize\s*\(""", re.IGNORECASE),
            re.compile(r"""\byaml_parse\s*\(""", re.IGNORECASE),
        ),
        sanitizers=("json_decode(", "hash_hmac(", "openssl_verify("),
        direct_source_bonus=50, propagated_bonus=40,
        sanitizer_penalty=40, prepared_stmt_penalty=0,
        descripcion=(
            "unserialize() reconstruye objetos PHP a partir de una cadena controlada "
            "por el usuario. Si existen clases con métodos mágicos (__wakeup, __destruct) "
            "en el proyecto, el atacante puede encadenarlos para ejecutar código (POP chain)."
        ),
        impacto=(
            "RCE mediante POP chains, borrado de ficheros, SSRF interno, "
            "o bypass de autenticación dependiendo de las clases disponibles."
        ),
        solucion=(
            "Sustituye unserialize() por json_decode() para transferir datos simples. "
            "Si necesitas serializar objetos, usa una librería con firma HMAC "
            "que verifique la integridad antes de deserializar."
        ),
        ejemplo_seguro=(
            "// Mal\n"
            "$obj = unserialize($_COOKIE['data']);\n\n"
            "// Bien: JSON para datos simples\n"
            "$data = json_decode($_COOKIE['data'], true);\n\n"
            "// Bien: payload firmado\n"
            "[$payload, $sig] = explode('.', $_COOKIE['data'], 2);\n"
            "if (!hash_equals(hash_hmac('sha256', $payload, SECRET), $sig)) {\n"
            "    die('Firma inválida');\n"
            "}\n"
            "$obj = unserialize(base64_decode($payload));"
        ),
    ),

    VulnRule(
        vuln_type="SSRF",
        cwe_id=918, cvss_base=8.6, owasp="A10:2021", severity="HIGH",
        sinks=(
            re.compile(
                r"""\b(?:file_get_contents|curl_init|curl_setopt|fopen|"""
                r"""SoapClient|simplexml_load_file|get_headers)\s*\(""",
                re.IGNORECASE,
            ),
        ),
        sanitizers=("FILTER_VALIDATE_URL", "parse_url(", "in_array(", "preg_match("),
        direct_source_bonus=40, propagated_bonus=30,
        sanitizer_penalty=45, prepared_stmt_penalty=0,
        descripcion=(
            "El servidor realiza una petición HTTP o de fichero a una URL construida "
            "con input del usuario. El atacante puede apuntar a recursos internos "
            "inaccesibles desde el exterior (metadata cloud, servicios internos, localhost)."
        ),
        impacto=(
            "Acceso al servicio de metadatos cloud (AWS IMDSv1, GCP), "
            "escaneo de puertos internos, lectura de ficheros locales (file://), "
            "y posible pivoting hacia la red interna."
        ),
        solucion=(
            "Valida la URL contra una lista blanca de dominios/esquemas permitidos. "
            "Bloquea IPs privadas (127.x, 10.x, 192.168.x, 169.254.x) y esquemas "
            "no-HTTP (file://, gopher://, dict://). Usa una librería dedicada."
        ),
        ejemplo_seguro=(
            "$url = $_GET['url'];\n"
            "$parsed = parse_url($url);\n"
            "$allowed_hosts = ['api.example.com', 'cdn.example.com'];\n"
            "if (!in_array($parsed['host'] ?? '', $allowed_hosts, true)) {\n"
            "    die('Host no permitido');\n"
            "}\n"
            "$response = file_get_contents($url);"
        ),
    ),

    VulnRule(
        vuln_type="Open Redirect",
        cwe_id=601, cvss_base=6.1, owasp="A01:2021", severity="MEDIUM",
        sinks=(
            re.compile(r"""header\s*\(\s*['""]Location\s*:""", re.IGNORECASE),
        ),
        sanitizers=("FILTER_VALIDATE_URL", "parse_url(", "in_array(", "preg_match("),
        direct_source_bonus=35, propagated_bonus=25,
        sanitizer_penalty=50, prepared_stmt_penalty=0,
        descripcion=(
            "La cabecera Location se construye con un valor controlado por el usuario "
            "sin validar el destino. El atacante puede crear URLs de phishing que "
            "parecen legítimas pero redirigen a sitios maliciosos."
        ),
        impacto=(
            "Phishing creíble (el dominio origen es legítimo), robo de credenciales, "
            "bypass de referrer checks, y distribución de malware."
        ),
        solucion=(
            "Valida el destino contra una lista blanca de URLs o dominios permitidos. "
            "Si solo necesitas redirecciones internas, usa rutas relativas en lugar "
            "de URLs absolutas."
        ),
        ejemplo_seguro=(
            "$allowed = ['/dashboard', '/profile', '/home'];\n"
            "$dest = $_GET['next'] ?? '/home';\n"
            "if (!in_array($dest, $allowed, true)) {\n"
            "    $dest = '/home';\n"
            "}\n"
            "header('Location: ' . $dest);\n"
            "exit;"
        ),
    ),

    VulnRule(
        vuln_type="Path Traversal",
        cwe_id=22, cvss_base=7.5, owasp="A01:2021", severity="HIGH",
        sinks=(
            re.compile(
                r"""\b(?:file_get_contents|file_put_contents|fopen|"""
                r"""readfile|unlink|rename|copy|move_uploaded_file)\s*\(""",
                re.IGNORECASE,
            ),
        ),
        sanitizers=("realpath(", "basename(", "str_replace('../'", "preg_replace"),
        direct_source_bonus=40, propagated_bonus=30,
        sanitizer_penalty=50, prepared_stmt_penalty=0,
        descripcion=(
            "Una operación de fichero usa una ruta construida con input del usuario. "
            "El atacante puede usar secuencias ../ para salir del directorio previsto "
            "y acceder a ficheros arbitrarios del sistema."
        ),
        impacto=(
            "Lectura de ficheros sensibles (/etc/passwd, .env, claves privadas), "
            "sobrescritura de ficheros de configuración, y en combinación con "
            "otras vulns puede llevar a RCE."
        ),
        solucion=(
            "Usa realpath() para resolver la ruta canónica y verifica que empieza "
            "con el directorio base permitido. Nunca confíes en basename() solo, "
            "ya que no neutraliza null bytes en PHP < 5.3."
        ),
        ejemplo_seguro=(
            "$base = realpath('/var/www/uploads');\n"
            "$path = realpath($base . '/' . $_GET['file']);\n"
            "if ($path === false || strpos($path, $base) !== 0) {\n"
            "    die('Acceso denegado');\n"
            "}\n"
            "readfile($path);"
        ),
    ),

    VulnRule(
        vuln_type="XXE",
        cwe_id=611, cvss_base=8.6, owasp="A05:2021", severity="HIGH",
        sinks=(
            re.compile(r"""\blibxml_disable_entity_loader\s*\(\s*false\s*\)""", re.IGNORECASE),
            re.compile(r"""\bsimplexml_load_string\s*\(""", re.IGNORECASE),
            re.compile(r"""\bnew\s+DOMDocument\b""", re.IGNORECASE),
        ),
        sanitizers=("LIBXML_NOENT", "LIBXML_NONET", "libxml_disable_entity_loader(true"),
        direct_source_bonus=20, propagated_bonus=15,
        sanitizer_penalty=80, prepared_stmt_penalty=0,
        descripcion=(
            "El parser XML está configurado para procesar entidades externas. "
            "Un documento XML malicioso puede referenciar ficheros locales o "
            "hacer peticiones a hosts internos a través de la expansión de entidades."
        ),
        impacto=(
            "Lectura de ficheros locales, SSRF, denegación de servicio "
            "(billion laughs attack) y en algunos parsers ejecución de código."
        ),
        solucion=(
            "Desactiva las entidades externas con libxml_disable_entity_loader(true) "
            "antes de parsear (PHP < 8.0). En PHP 8+ está desactivado por defecto. "
            "Pasa LIBXML_NONET para prevenir peticiones de red."
        ),
        ejemplo_seguro=(
            "libxml_disable_entity_loader(true); // PHP < 8.0\n"
            "$dom = new DOMDocument();\n"
            "$dom->loadXML($xml, LIBXML_NONET | LIBXML_NOERROR);\n\n"
            "// O con SimpleXML:\n"
            "$obj = simplexml_load_string($xml, 'SimpleXMLElement',\n"
            "    LIBXML_NONET | LIBXML_NOERROR);"
        ),
    ),

    VulnRule(
        vuln_type="LDAP Injection",
        cwe_id=90, cvss_base=7.5, owasp="A03:2021", severity="HIGH",
        sinks=(
            re.compile(r"""\b(?:ldap_search|ldap_list|ldap_read)\s*\(""", re.IGNORECASE),
        ),
        sanitizers=("ldap_escape(",),
        direct_source_bonus=45, propagated_bonus=35,
        sanitizer_penalty=65, prepared_stmt_penalty=0,
        descripcion=(
            "Una consulta LDAP se construye concatenando datos del usuario sin escapar. "
            "El atacante puede manipular el filtro LDAP para obtener entradas no autorizadas "
            "o realizar ataques de bypass de autenticación."
        ),
        impacto=(
            "Bypass de autenticación LDAP, extracción de entradas del directorio, "
            "enumeración de usuarios y grupos."
        ),
        solucion=(
            "Usa ldap_escape() con el flag LDAP_ESCAPE_FILTER para valores en el filtro "
            "y LDAP_ESCAPE_DN para componentes de DN."
        ),
        ejemplo_seguro=(
            "$user = ldap_escape($_POST['username'], '', LDAP_ESCAPE_FILTER);\n"
            "$filter = \"(&(uid=$user)(objectClass=posixAccount))\";\n"
            "$result = ldap_search($conn, $base, $filter);"
        ),
    ),

    VulnRule(
        vuln_type="XPath Injection",
        cwe_id=643, cvss_base=7.5, owasp="A03:2021", severity="HIGH",
        sinks=(
            re.compile(r"""->xpath\s*\(""", re.IGNORECASE),
            re.compile(r"""\bevaluate\s*\([^)]*\$""", re.IGNORECASE),
        ),
        sanitizers=("addslashes(", "str_replace(\"'\""),
        direct_source_bonus=40, propagated_bonus=30,
        sanitizer_penalty=50, prepared_stmt_penalty=0,
        descripcion=(
            "Una expresión XPath se construye concatenando input del usuario. "
            "El atacante puede inyectar predicados XPath para leer nodos no autorizados "
            "o eludir condiciones de autenticación."
        ),
        impacto=(
            "Extracción de datos del documento XML, bypass de autenticación basada "
            "en XML, y enumeración de la estructura del documento."
        ),
        solucion=(
            "Usa XPath parametrizado con la extensión DOM o una librería que soporte "
            "variables XPath. Si no es posible, escapa las comillas simples "
            "antes de interpolar."
        ),
        ejemplo_seguro=(
            "// Escapar comillas simples si no hay soporte de parámetros\n"
            "$user = str_replace(\"'\", \"&apos;\", $_GET['user']);\n"
            "$expr = \"//user[name='$user']\";\n"
            "$result = $xml->xpath($expr);"
        ),
    ),

    VulnRule(
        vuln_type="Header Injection (CRLF)",
        cwe_id=113, cvss_base=6.1, owasp="A03:2021", severity="MEDIUM",
        sinks=(
            re.compile(r"""\bheader\s*\(""", re.IGNORECASE),
            re.compile(r"""\bsetcookie\s*\(""", re.IGNORECASE),
        ),
        sanitizers=("str_replace(\"\\n\"", "str_replace(\"\\r\"", "preg_replace"),
        direct_source_bonus=35, propagated_bonus=25,
        sanitizer_penalty=55, prepared_stmt_penalty=0,
        descripcion=(
            "El valor de una cabecera HTTP se construye con input del usuario sin "
            "eliminar saltos de línea (\\r\\n). El atacante puede inyectar cabeceras "
            "adicionales o dividir la respuesta HTTP."
        ),
        impacto=(
            "Inyección de cabeceras HTTP arbitrarias, HTTP response splitting, "
            "XSS a través de Set-Cookie, y cache poisoning."
        ),
        solucion=(
            "Elimina o rechaza cualquier valor que contenga \\r o \\n antes de "
            "pasarlo a header() o setcookie(). En PHP ≥ 7.2 header() lanza una "
            "excepción si detecta CRLF, pero no confíes solo en eso."
        ),
        ejemplo_seguro=(
            "$value = preg_replace('/[\\r\\n]+/', '', $_GET['lang']);\n"
            "header('Content-Language: ' . $value);"
        ),
    ),
]


# ===========================================================================
# 3. Finding → dict with exact keys the frontend expects
# ===========================================================================

@dataclass(order=True)
class Finding:
    line: int
    vuln_type: str
    severity: str           # internal severity key
    cvss: float
    cwe_id: int
    owasp: str
    confidence: int
    descripcion: str
    impacto: str
    solucion: str
    ejemplo_seguro: str
    source_line: str        # the actual PHP line that triggered the finding
    taint_chain: List[str] = field(default_factory=list, compare=False)
    matched_sink: str = field(default="", compare=False)
    tainted_var: str = field(default="", compare=False)

    def to_dict(self) -> Dict:
        return {
            # ── Fields consumed by mostrarVulnerabilidades() ──
            "tipo":          self.vuln_type,
            "linea":         self.line,
            "severidad":     _SEV_ES.get(self.severity, "Media"),
            "cwe":           f"CWE-{self.cwe_id}",
            "owasp":         self.owasp,
            "confianza":     f"{self.confidence}%",
            "descripcion":   self.descripcion,
            "impacto":       self.impacto,
            "solucion":      self.solucion,
            "ejemplo_seguro": self.ejemplo_seguro,
            "codigo":        self.source_line,
            # ── Extra metadata (not rendered but useful for the backend) ──
            "cvss_base":     self.cvss,
            "cadena_taint":  self.taint_chain,
            "sink":          self.matched_sink,
        }


# ===========================================================================
# 4. Static Analyzer
# ===========================================================================

class StaticAnalyzer:

    CONFIDENCE_THRESHOLD: ClassVar[int] = 35
    CONTEXT_WINDOW: ClassVar[int] = 4

    @classmethod
    def run(cls, code: str) -> List[Dict]:
        lines   = code.splitlines()
        engine  = TaintEngine()
        findings: List[Finding] = []
        seen: Set[Tuple[int, str]] = set()

        for i, line in enumerate(lines, start=1):
            stripped = line.strip()
            if stripped.startswith(("//", "#", "*", "/*")):
                continue

            state = engine.process_line(line, i)

            ctx_start = max(0, i - 1 - cls.CONTEXT_WINDOW)
            ctx_end   = min(len(lines), i + cls.CONTEXT_WINDOW)
            context   = "\n".join(lines[ctx_start:ctx_end])

            for rule in VULN_RULES:
                for sink_pat in rule.sinks:
                    sink_match = sink_pat.search(line)
                    if not sink_match:
                        continue

                    sink_text  = sink_match.group(0)
                    taint_info = state.any_tainted_in(line)
                    direct     = state.superglobal_in(line)

                    if not taint_info and not direct:
                        continue

                    tainted_var_name = (
                        taint_info.var_name if taint_info else "entrada directa"
                    )
                    chain = (
                        taint_info.chain + [
                            f"línea {i}: {taint_info.var_name} → {sink_text[:50]}"
                        ]
                        if taint_info
                        else [f"línea {i}: superglobal directa → {sink_text[:50]}"]
                    )

                    # ── Confidence ──
                    confidence = 50
                    if direct:
                        confidence += rule.direct_source_bonus
                    if taint_info:
                        confidence += int(rule.propagated_bonus * taint_info.strength)
                    if any(s in context for s in rule.sanitizers):
                        confidence -= rule.sanitizer_penalty
                    if rule.prepared_stmt_penalty:
                        if any(p in context for p in (
                            "prepare(", "bindParam(", "bindValue(", "bind_param(", "PDO::"
                        )):
                            confidence -= rule.prepared_stmt_penalty
                    confidence = max(0, min(100, confidence))

                    if confidence < cls.CONFIDENCE_THRESHOLD:
                        continue

                    key = (i, rule.vuln_type)
                    if key in seen:
                        continue
                    seen.add(key)

                    findings.append(Finding(
                        line          = i,
                        vuln_type     = rule.vuln_type,
                        severity      = rule.severity,
                        cvss          = rule.cvss_base,
                        cwe_id        = rule.cwe_id,
                        owasp         = rule.owasp,
                        confidence    = confidence,
                        descripcion   = rule.descripcion,
                        impacto       = rule.impacto,
                        solucion      = rule.solucion,
                        ejemplo_seguro = rule.ejemplo_seguro,
                        source_line   = line.strip(),
                        taint_chain   = chain,
                        matched_sink  = sink_text[:80],
                        tainted_var   = tainted_var_name,
                    ))

        findings.sort(key=lambda f: (-f.cvss, -f.confidence, f.line))
        return [v.to_dict() for v in findings]

    @classmethod
    def summary(cls, results: List[Dict]) -> Dict:
        counts: Dict[str, int]     = defaultdict(int)
        sev_counts: Dict[str, int] = defaultdict(int)
        for r in results:
            counts[r["tipo"]]         += 1
            sev_counts[r["severidad"]] += 1
        return {
            "total":        len(results),
            "por_tipo":     dict(counts),
            "por_severidad": dict(sev_counts),
        }


# ===========================================================================
# 5. CLI
# ===========================================================================

if __name__ == "__main__":
    import json, sys

    if len(sys.argv) < 2:
        print("Uso: python static_analyzer.py <fichero.php> [--min-confianza N]")
        sys.exit(1)

    min_conf = 35
    if "--min-confianza" in sys.argv:
        idx      = sys.argv.index("--min-confianza")
        min_conf = int(sys.argv[idx + 1])
    StaticAnalyzer.CONFIDENCE_THRESHOLD = min_conf

    with open(sys.argv[1], "r", encoding="utf-8", errors="replace") as fh:
        source = fh.read()

    results = StaticAnalyzer.run(source)
    summary = StaticAnalyzer.summary(results)

    print(json.dumps({"resumen": summary, "hallazgos": results}, indent=2, ensure_ascii=False))
    print(f"\n[{summary['total']} hallazgo(s) — umbral de confianza: {min_conf}%]")