
rule File_11c9102bb80ad099d8d0b1b58cf6d10c {
    strings:
        $file_hash = "11c9102bb80ad099d8d0b1b58cf6d10c"
    condition:
        $file_hash
}
