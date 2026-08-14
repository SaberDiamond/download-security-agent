from pypdf import PdfWriter


writer = PdfWriter()

writer.add_blank_page(width=612, height=792)

with open("samples/test_embedded.txt", "w") as test_file:
    test_file.write("This is a harmless embedded-file test.")

with open("samples/test_embedded.txt", "rb") as embedded_file:
    writer.add_attachment(
        "test_embedded.txt",
        embedded_file.read()
    )

with open("samples/test_embedded.pdf", "wb") as output_file:
    writer.write(output_file)

print("Created samples/test_embedded.pdf")