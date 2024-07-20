# FirmRec Pipeline


FirmRec involves multiple steps to perform end-to-end recurring vulnerability detection. To ease the use, we tend to integrate all the steps into this nutshell module, i.e., `firmrec.pipeline`. 

Following command runs all steps in order

```
python -m firmrec.pipeline all
```


You can see the steps by running `python -m firmrec.pipeline`, which ask for the index of the step to run. Each step of pipeline will first generate a command lists named after the step name under `inout/cmds` directory, and then generate a log file during runing, which records output and error messages. The internal results of each step will also be recorded under the inout directory accordingly.

1. Run prepare steps

```
python -m firmrec.pipeline 1.1 1.2 1.3 1.4 1.5
```

2. Run input entry analysis

```
python -m firmrec.pipeline 2.1 2.2 2.3 2.4
```

3. Run signature generation
```
python -m firmrec.pipeline 3.1 3.2 3.3
```

```
python -m firmrec.diag collect --input inout/sig_simexp_inputs/ --output inout/sig_simexp_results/ --save-space -d
```

4. Run vulnerability detection and show results
```
python -m firmrec.pipeline 4.1 4.2 4.3 4.4
```

Currently, the pipeline involves most of FirmRec modules except. We are still working
