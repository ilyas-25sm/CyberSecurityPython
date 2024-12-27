
rule File_406f87ce71665e4f433af2c0a1c4e046 {
    strings:
        $file_hash = "406f87ce71665e4f433af2c0a1c4e046"
    condition:
        $file_hash
}
