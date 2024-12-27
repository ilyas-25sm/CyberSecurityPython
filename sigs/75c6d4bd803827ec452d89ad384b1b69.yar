
rule File_75c6d4bd803827ec452d89ad384b1b69 {
    strings:
        $file_hash = "75c6d4bd803827ec452d89ad384b1b69"
    condition:
        $file_hash
}
