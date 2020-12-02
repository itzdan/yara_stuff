rule JScertenroll
{
        meta:
        author = "Subtee"
        info = " https://gist.github.com/secdev-01/9ddc564b374cd08d3dab8e98eaed8e83"

    strings:
	$s0 = "<scriptlet>" wide
	$s1 = "JSCertEnroll" wide
	$s2 = "function InvokeCreateCertificate(certSubject, isCA)" wide
	$h1 = "6e 65 77 20 41 63 74 69 76 65 58 4f 62 6a 65 63 74 28 22 58 35 30 39 45 6e 72 6f 6c 6c 6d 65 6e 74 2e 43 58 35 30 39 43 65 72 74 69 66 69 63 61 74 65 52 65 71 75 65 73 74 43 65 72 74 69 66 69 63 61 74 65 22 29"
	$s4 = "cert.InitializeFromPrivateKey" wide
	$s5 = "enrollment.InitializeFromRequest(cert)" wide
	$h2 = "6e 65 77 20 41 63 74 69 76 65 58 4f 62 6a 65 63 74 28 22 57 53 63 72 69 70 74 2e 53 68 65 6c 6c 22 29"
	$s7 = "oShell.Exec('certutil -store -user ')" wide
	$s8 = "oShell.Exec('certutil -exportPFX" wide
	$s9 = "InvokeCreateCertificate" wide

	condition:
	all of them

}
