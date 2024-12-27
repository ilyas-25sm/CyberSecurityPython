
rule File_3b389edf7869657322ab314fe0c8ecf1 {
    strings:
        $file_hash = "3b389edf7869657322ab314fe0c8ecf1"
    condition:
        $file_hash
}
