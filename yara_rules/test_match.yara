rule Test_Malicious_String
{
    strings:
        $bad = "malicious_activity_here"
    condition:
        $bad
}
