
rule File_8d14660b27eda97899430247d7499c02 {
    strings:
        $file_hash = "8d14660b27eda97899430247d7499c02"
    condition:
        $file_hash
}
