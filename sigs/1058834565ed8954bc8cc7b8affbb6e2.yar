
rule File_1058834565ed8954bc8cc7b8affbb6e2 {
    strings:
        $file_hash = "1058834565ed8954bc8cc7b8affbb6e2"
    condition:
        $file_hash
}
