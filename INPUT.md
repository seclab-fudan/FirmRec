# Structure of Inputs

You should prepare an inout directory for using FirmRec in your own dataset.

The dataset is structured with three parts:

1. Known vulnerability information at `inout/vuln_info`
2. Target firmware images at `inout/firmware/images`
3. Task list specified by `inout/experiment.json`

We will detail them next.

## Known Vulnerability Information

For a known vulnerability, please create a vulnerability directory with `intout/vuln_info/<VULN_VENDOR>/<VULN_NAME>`.
Then place a vulnerable firmware image and create a `meta.json` file in that folder.
Make sure the firmware image name contains only digits, letters, '-' or '_'.
The `meta.json` file must contain essential vulnerability information for analysis, here is a template:

```json
{
    "firmware_filename": "The firmware image name",
    "input": {
        "kv" {
            "KEY": "VALUE", ...
        }
    }
}

OR

{
    "firmware_filename": "The firmware image name",
    "input": {
        "raw": [
            "Raw input encoded with base64"
        ]
    }
}
```

The `input` field is a parsed proof-of-concept input. For inputs that read with structure input reading functions (e.g., get_value("KEY")), put all key-value pairs under the "kv" field. For inputs that read with raw input reading functions (e.g., recv()), encode the input with base64, and then put it under the "raw" field.

## Target firmware images

The `inout/firmware/images` directory consists of images where FirmRec detects recurring vulnerabilities.
The image should be placed at corresponding vendor directory, i.e., `inout/firmware/images/<VENDOR>/<IMAGE>`

## Task List

The `experiment.json` file specifies the signature extraction (with vulnerability name) and vulnerability detection tasks. The following showcases a template:

```json
{
    "name": "Any name your like",
    "vulns": [
        "<VULN_VENDOR>/<VULN_NAME>", ...
    ],
    "images": {
        "<VENDOR>/<IMAGE>", ...
    }
}
```