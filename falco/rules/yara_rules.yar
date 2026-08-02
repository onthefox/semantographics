/*
 * Very small, generic Metasploit‑style payload signature.
 * It looks for the classic "/bin/sh" string that many shellcode variants
 * embed and for a characteristic stub pattern used by the msfvenom
 * "linux/x86/meterpreter" payloads.
 *
 * Real‑world deployments should use a much richer rule set (e.g. the
 * public "malware‑yara" repo) – this is only a proof‑of‑concept.
 */

rule MetasploitShellcode
{
    meta:
        description = "Detects typical Metasploit x86 shellcode"
        author      = "LLM‑Sec"
        reference   = "https://github.com/rapid7/metasploit‑framework"
    strings:
        $sh_str     = "/bin/sh" nocase
        $xor_stub   = { 31 c0 50 68 2f 2f 73 68 68 2f 62 69 6e 89 e3 50 53 89 e1 31 d2 b0 0b cd 80 }
        // xor_stub is a classic 28‑byte execve("/bin/sh") stub
    condition:
        $sh_str and $xor_stub
}
