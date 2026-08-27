from pypdf import PdfWriter


writer = PdfWriter()

writer.add_blank_page(width=612, height=792)

test_file = "samples/test_embedded.js"

with open(test_file, "w") as file:
    file.write("console.log('Harmless embedded JavaScript test');")

with open(test_file, "rb") as embedded_file:
    writer.add_attachment(
        "test_embedded.js",
        embedded_file.read()
    )

with open("samples/test_embedded_js.pdf", "wb") as output_file:
    writer.write(output_file)

print("Created samples/test_embedded_js.pdf")