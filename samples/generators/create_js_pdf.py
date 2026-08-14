from pypdf import PdfWriter


writer = PdfWriter()

writer.add_blank_page(width=612, height=792)

writer.add_js("app.alert('Security Agent test PDF');")

with open("samples/test_js.pdf", "wb") as output_file:
    writer.write(output_file)

print("Created samples/test_js.pdf")