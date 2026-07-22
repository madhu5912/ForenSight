"""
ForenSight - Known-answer test-data generator.

Manufactures controlled cases whose correct verdicts you already know, so you can
prove the pipeline works before touching real data.
"""
import os

OUT = "sample_evidence"
os.makedirs(OUT, exist_ok=True)

# A minimal valid 1x1 PNG (header + tiny body).
PNG = bytes.fromhex(
    "89504e470d0a1a0a0000000d4948445200000001000000010806"
    "0000001f15c4890000000a49444154789c6360000002000154a2"
    "4f5f0000000049454e44ae426082"
)

with open(os.path.join(OUT, "clean_image.png"), "wb") as f:
    f.write(PNG)                              # correct: PNG bytes, .png name -> Low

with open(os.path.join(OUT, "disguised.jpg"), "wb") as f:
    f.write(PNG)                              # spoofed: PNG bytes, .jpg name -> High

with open(os.path.join(OUT, "secret.pdf"), "wb") as f:
    f.write(PNG)                              # spoofed: PNG bytes, .pdf name -> High

with open(os.path.join(OUT, "invoice.pdf.exe"), "wb") as f:
    f.write(PNG)                              # double extension + mismatch -> High

with open(os.path.join(OUT, ".hidden_note.txt"), "w") as f:
    f.write("hidden file content")           # hidden file -> Low/Medium

with open(os.path.join(OUT, "encrypted.bin"), "wb") as f:
    f.write(os.urandom(4096))                # high entropy -> relevance boost

print(f"Created test files in ./{OUT}/")
