# WARNING
Deprecated, use https://github.com/Azvanzed/CVE-2024-44083 instead.

# IdaMeme
Crashes ida on static analyses.

POC that involves overwhelming the IDA program with numerous jumps at the executable entry point, causing it to crash prior to reaching the actual entry point. To achieve this, one can generate a fresh section and consecutively link numerous jumps while ensuring that the final jump corresponds to the payload from where the actual entry point will be invoked.

It's likely that the crash occurred because IDA attempted to analyze the code for the jmp instructions, which can take up to 100 ms. With approximately 20,000 jmps, this amount of processing time can overwhelm IDA and result in a crash.

The diagram delineates the process of its creation:

![image](https://user-images.githubusercontent.com/107370797/231252749-1b454d11-0717-4314-b8a9-4201be8b655f.png)

Warning:
- Security checks have to be disable.
- Does not support packers.

Media:

https://user-images.githubusercontent.com/107370797/231253036-d2a449b3-9e29-490f-a89f-81ffb3aabf8b.mp4

