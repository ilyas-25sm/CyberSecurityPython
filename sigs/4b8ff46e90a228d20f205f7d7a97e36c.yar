
rule File_4b8ff46e90a228d20f205f7d7a97e36c {
    strings:
        $file_hash = "4b8ff46e90a228d20f205f7d7a97e36c"
    condition:
        $file_hash
}
