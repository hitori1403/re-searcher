#!/bin/env python

from construct import *

fileName = "Synology_BC500_1.0.6_0294.sa.bin"

firmwareFormat = Struct(
    "header"
    / Struct(
        "version" / PaddedString(8, "ascii"),
        "firmware_version" / PaddedString(16, "ascii"),
        "model" / PaddedString(8, "ascii"),
        Padding(56),  # padded with 0
        Bytes(16),
        Padding(16),  # padded with 0
        Bytes(4),
        "partition_count" / BytesInteger(2, swapped=True),
        "pre_script" / Prefixed(BytesInteger(4, swapped=True), Compressed(GreedyBytes, "zlib")),
        "post_script" / Prefixed(BytesInteger(4, swapped=True), Compressed(GreedyBytes, "zlib")),
    ),
    "partitions"
    / Array(
        this.header.partition_count,
        Struct(
            "name" / PaddedString(64, "ascii"),
            "script_length" / BytesInteger(4, swapped=True),
            "image_length" / BytesInteger(4, swapped=True),
            "script" / FixedSized(this.script_length, Compressed(GreedyBytes, "zlib")),
            "image" / FixedSized(this.image_length, Compressed(GreedyBytes, "zlib")),
        ),
    ),
    "signature" / Bytes(512),
)

with open(fileName, mode="rb") as fileObject:
    fileContent = fileObject.read()
    firmwareObject = firmwareFormat.parse(fileContent)

    for partition in firmwareObject["partitions"]:
        with open(fileName + "_" + partition["name"].replace("\x00", "") + ".sh", mode="wb") as writeObject:
            writeObject.write(partition["script"])
        with open(fileName + "_" + partition["name"].replace("\x00", "") + ".bin", mode="wb") as writeObject:
            writeObject.write(partition["image"])

    with open(fileName + "_pre.sh", mode="wb") as writeObject:
        writeObject.write(firmwareObject["header"]["pre_script"])

    with open(fileName + "_post.sh", mode="wb") as writeObject:
        writeObject.write(firmwareObject["header"]["post_script"])
