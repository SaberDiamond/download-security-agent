from pypdf import PdfWriter
from pypdf.generic import (
    ArrayObject,
    DictionaryObject,
    NameObject,
    NumberObject,
    TextStringObject,
)


writer = PdfWriter()

page = writer.add_blank_page(width=612, height=792)


# 1. JavaScript
writer.add_js("app.alert('Test JavaScript')")


# 2. OpenAction
action = DictionaryObject({
    NameObject("/Type"): NameObject("/Action"),
    NameObject("/S"): NameObject("/JavaScript"),
    NameObject("/JS"): TextStringObject(
        "app.alert('Test PDF action')"
    ),
})

writer._root_object.update({
    NameObject("/OpenAction"): writer._add_object(action)
})


# 3. External URL
url = "https://www.youtube.com"

link_annotation = DictionaryObject({
    NameObject("/Type"): NameObject("/Annot"),
    NameObject("/Subtype"): NameObject("/Link"),
    NameObject("/Rect"): ArrayObject([
        NumberObject(100),
        NumberObject(650),
        NumberObject(300),
        NumberObject(680),
    ]),
    NameObject("/Border"): ArrayObject([
        NumberObject(0),
        NumberObject(0),
        NumberObject(1),
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


# Save the test PDF
output_path = "samples/test_high.pdf"

with open(output_path, "wb") as output_file:
    writer.write(output_file)

print(f"Created {output_path}")