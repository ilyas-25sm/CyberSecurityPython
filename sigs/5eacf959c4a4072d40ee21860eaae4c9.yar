
rule File_5eacf959c4a4072d40ee21860eaae4c9 {
    strings:
        $file_hash = "5eacf959c4a4072d40ee21860eaae4c9"
    condition:
        $file_hash
}
