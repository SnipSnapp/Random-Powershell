[Net.ServicePointManager]::ServerCertificateValidationCallback = { $true };
$URI= "https://<YOUR WEBSITE>";
$webreq=[Net.HttpWebRequest]::Create($URI);
$webreq.ServicePoint;$webreq.GetResponse()|Out-Null;
$webReq.Servicepoint.Certificate|Select Issuer;
$webreq.Servicepoint.Certificate.GetIssuerName();
