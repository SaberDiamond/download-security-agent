from pypdf import PdfWriter
from pypdf.generic import (
    ArrayObject,
    DictionaryObject,
    NameObject,
    FloatObject,
    TextStringObject,
)


writer = PdfWriter()

page = writer.add_blank_page(width=612, height=792)

url = "https://www.youtube.com"

link_annotation = DictionaryObject()

link_annotation.update({
    NameObject("/Type"): NameObject("/Annot"),
    NameObject("/Subtype"): NameObject("/Link"),
    NameObject("/Rect"): ArrayObject([
        FloatObject(100),
        FloatObject(650),
        FloatObject(300),
        FloatObject(680),
    ]),
    NameObject("/Border"): ArrayObject([
        FloatObject(0),
        FloatObject(0),
        FloatObject(1),
    ]),
    NameObject("/A"): DictionaryObject({
        NameObject("/Type"): NameObject("/Action"),
        NameObject("/S"): NameObject("/URI"),
        NameObject("/URI"): TextStringObject(url),
    }),
})

page[NameObject("/Annots")] = ArrayObject([
    writer._add_object(link_annotation)
])

with open("samples/test_url.pdf", "wb") as output_file:
    writer.write(output_file)

print("Created samples/test_url.pdf")