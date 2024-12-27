
rule File_2cead80b4fbdfcbd85e6c3738d711dc0 {
    strings:
        $file_hash = "2cead80b4fbdfcbd85e6c3738d711dc0"
    condition:
        $file_hash
}
