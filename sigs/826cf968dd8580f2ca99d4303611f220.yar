
rule File_826cf968dd8580f2ca99d4303611f220 {
    strings:
        $file_hash = "826cf968dd8580f2ca99d4303611f220"
    condition:
        $file_hash
}
