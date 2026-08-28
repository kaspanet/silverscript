//! JSON formatting for portable Sil artifacts.

use std::io::{self, Write};

use serde::Serialize;
use serde_json::ser::{Formatter, PrettyFormatter};

const BYTES_PER_LINE: usize = 64;
const INDENT: &[u8] = b"  ";

/// Serialize a value as readable JSON while keeping byte arrays compact.
pub fn to_pretty_json<T>(value: &T) -> serde_json::Result<String>
where
    T: ?Sized + Serialize,
{
    let mut output = Vec::new();
    let formatter = ByteArrayPrettyFormatter::new();
    let mut serializer = serde_json::Serializer::with_formatter(&mut output, formatter);
    value.serialize(&mut serializer)?;
    Ok(String::from_utf8(output).expect("the JSON serializer emits UTF-8"))
}

struct ByteArrayPrettyFormatter<'a> {
    inner: PrettyFormatter<'a>,
    depth: usize,
    indent: &'a [u8],
}

impl ByteArrayPrettyFormatter<'static> {
    fn new() -> Self {
        Self { inner: PrettyFormatter::with_indent(INDENT), depth: 0, indent: INDENT }
    }
}

macro_rules! delegate {
    ($name:ident $(, $arg:ident: $ty:ty)*) => {
        fn $name<W>(&mut self, writer: &mut W, $($arg: $ty),*) -> io::Result<()>
        where
            W: ?Sized + Write,
        {
            self.inner.$name(writer, $($arg),*)
        }
    };
}

impl Formatter for ByteArrayPrettyFormatter<'_> {
    delegate!(begin_array_value, first: bool);
    delegate!(end_array_value);
    delegate!(begin_object_key, first: bool);
    delegate!(begin_object_value);
    delegate!(end_object_value);

    // Keep byte arrays compact without changing ordinary array formatting.
    fn write_byte_array<W>(&mut self, writer: &mut W, bytes: &[u8]) -> io::Result<()>
    where
        W: ?Sized + Write,
    {
        if bytes.len() <= BYTES_PER_LINE {
            writer.write_all(b"[")?;
            write_bytes(writer, bytes)?;
            return writer.write_all(b"]");
        }

        writer.write_all(b"[")?;
        for (index, chunk) in bytes.chunks(BYTES_PER_LINE).enumerate() {
            writer.write_all(b"\n")?;
            write_indent(writer, self.depth + 1, self.indent)?;
            write_bytes(writer, chunk)?;
            if index + 1 < bytes.len().div_ceil(BYTES_PER_LINE) {
                writer.write_all(b",")?;
            }
        }
        writer.write_all(b"\n")?;
        write_indent(writer, self.depth, self.indent)?;
        writer.write_all(b"]")
    }

    // Delegate ordinary formatting while mirroring PrettyFormatter's container depth.
    fn begin_array<W>(&mut self, writer: &mut W) -> io::Result<()>
    where
        W: ?Sized + Write,
    {
        self.depth += 1;
        self.inner.begin_array(writer)
    }

    fn end_array<W>(&mut self, writer: &mut W) -> io::Result<()>
    where
        W: ?Sized + Write,
    {
        self.depth -= 1;
        self.inner.end_array(writer)
    }

    fn begin_object<W>(&mut self, writer: &mut W) -> io::Result<()>
    where
        W: ?Sized + Write,
    {
        self.depth += 1;
        self.inner.begin_object(writer)
    }

    fn end_object<W>(&mut self, writer: &mut W) -> io::Result<()>
    where
        W: ?Sized + Write,
    {
        self.depth -= 1;
        self.inner.end_object(writer)
    }
}

fn write_bytes<W>(writer: &mut W, bytes: &[u8]) -> io::Result<()>
where
    W: ?Sized + Write,
{
    for (index, byte) in bytes.iter().enumerate() {
        if index > 0 {
            writer.write_all(b", ")?;
        }
        write!(writer, "{byte}")?;
    }
    Ok(())
}

fn write_indent<W>(writer: &mut W, depth: usize, indent: &[u8]) -> io::Result<()>
where
    W: ?Sized + Write,
{
    for _ in 0..depth {
        writer.write_all(indent)?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use serde::Serialize;

    use super::to_pretty_json;

    #[derive(Serialize)]
    struct Bytes(#[serde(with = "serde_bytes")] Vec<u8>);

    #[derive(Serialize)]
    struct Fixture {
        empty: Bytes,
        exact_line: Bytes,
        wrapped: Bytes,
        nested: Vec<Bytes>,
        ordinary: Vec<u16>,
    }

    #[test]
    fn formats_byte_arrays_without_compacting_ordinary_arrays() {
        let fixture = Fixture {
            empty: Bytes(Vec::new()),
            exact_line: Bytes((0..64).collect()),
            wrapped: Bytes((0..65).collect()),
            nested: vec![Bytes(vec![7, 8, 9])],
            ordinary: vec![1, 2, 3],
        };

        let json = to_pretty_json(&fixture).expect("fixture serializes");
        assert_eq!(
            json,
            r#"{
  "empty": [],
  "exact_line": [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40, 41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51, 52, 53, 54, 55, 56, 57, 58, 59, 60, 61, 62, 63],
  "wrapped": [
    0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40, 41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51, 52, 53, 54, 55, 56, 57, 58, 59, 60, 61, 62, 63,
    64
  ],
  "nested": [
    [7, 8, 9]
  ],
  "ordinary": [
    1,
    2,
    3
  ]
}"#
        );
    }
}
