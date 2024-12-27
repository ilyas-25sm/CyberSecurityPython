
rule File_50399f4e0e488843e5c5e07e02175214 {
    strings:
        $file_hash = "50399f4e0e488843e5c5e07e02175214"
    condition:
        $file_hash
}
