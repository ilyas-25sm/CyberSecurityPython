
rule File_678ea1a2e015529d4209cb1ba7dd165b {
    strings:
        $file_hash = "678ea1a2e015529d4209cb1ba7dd165b"
    condition:
        $file_hash
}
