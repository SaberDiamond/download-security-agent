from pypdf import PdfWriter


writer = PdfWriter()

writer.add_blank_page(width=612, height=792)

with open("samples/test_benign.pdf", "wb") as output_file:
    writer.write(output_file)

print("Created samples/test_benign.pdf")