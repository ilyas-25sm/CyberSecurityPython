
rule File_257dd3b590a45ada2b35f694ab09ebcd {
    strings:
        $file_hash = "257dd3b590a45ada2b35f694ab09ebcd"
    condition:
        $file_hash
}
