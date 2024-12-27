
rule File_a387135e7ebf20924ab893602bebfd77 {
    strings:
        $file_hash = "a387135e7ebf20924ab893602bebfd77"
    condition:
        $file_hash
}
