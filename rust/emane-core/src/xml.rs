use roxmltree::{Document, Node};
use std::ffi::{CStr, CString};
use std::os::raw::c_char;
use std::ptr;

#[repr(C)]
pub struct EmaneXmlAttr {
    pub name: *mut c_char,
    pub value: *mut c_char,
    pub next: *mut EmaneXmlAttr,
}

#[repr(C)]
pub struct EmaneXmlNode {
    pub name: *mut c_char,
    pub content: *mut c_char,
    pub children: *mut EmaneXmlNode,
    pub next: *mut EmaneXmlNode,
    pub attrs: *mut EmaneXmlAttr,
    pub type_: bool,
}

#[repr(C)]
pub struct EmaneXmlDoc {
    pub root: *mut EmaneXmlNode,
}

unsafe fn free_node(node: *mut EmaneXmlNode) {
    if node.is_null() {
        return;
    }
    let n = Box::from_raw(node);
    if !n.name.is_null() {
        drop(CString::from_raw(n.name));
    }
    if !n.content.is_null() {
        drop(CString::from_raw(n.content));
    }

    let mut attr = n.attrs;
    while !attr.is_null() {
        let a = Box::from_raw(attr);
        if !a.name.is_null() {
            drop(CString::from_raw(a.name));
        }
        if !a.value.is_null() {
            drop(CString::from_raw(a.value));
        }
        attr = a.next;
    }

    let mut child = n.children;
    while !child.is_null() {
        let next = (*child).next;
        free_node(child);
        child = next;
    }
}

fn build_node(node: Node) -> *mut EmaneXmlNode {
    let name = if node.is_element() {
        CString::new(node.tag_name().name()).unwrap().into_raw()
    } else {
        ptr::null_mut()
    };

    let content = if let Some(t) = node.text() {
        CString::new(t).unwrap().into_raw()
    } else {
        ptr::null_mut()
    };

    let mut first_attr: *mut EmaneXmlAttr = ptr::null_mut();
    let mut last_attr: *mut EmaneXmlAttr = ptr::null_mut();
    for attr in node.attributes() {
        let a = Box::into_raw(Box::new(EmaneXmlAttr {
            name: CString::new(attr.name()).unwrap().into_raw(),
            value: CString::new(attr.value()).unwrap().into_raw(),
            next: ptr::null_mut(),
        }));
        if first_attr.is_null() {
            first_attr = a;
        } else {
            unsafe {
                (*last_attr).next = a;
            }
        }
        last_attr = a;
    }

    let mut first_child: *mut EmaneXmlNode = ptr::null_mut();
    let mut last_child: *mut EmaneXmlNode = ptr::null_mut();
    for child in node.children() {
        if child.is_element() || child.is_text() {
            let c = build_node(child);
            if first_child.is_null() {
                first_child = c;
            } else {
                unsafe {
                    (*last_child).next = c;
                }
            }
            last_child = c;
        }
    }

    Box::into_raw(Box::new(EmaneXmlNode {
        name,
        content,
        children: first_child,
        next: ptr::null_mut(),
        attrs: first_attr,
        type_: node.is_element(),
    }))
}

#[no_mangle]
pub extern "C" fn emane_rs_xml_parse(uri: *const c_char) -> *mut EmaneXmlDoc {
    if uri.is_null() {
        return ptr::null_mut();
    }
    let path = unsafe { CStr::from_ptr(uri).to_string_lossy().into_owned() };

    let xml_text = match emane_plugin_api::xml_document::read(&path) {
        Ok(t) => t,
        Err(_) => return ptr::null_mut(),
    };

    let doc = match Document::parse_with_options(
        &xml_text,
        roxmltree::ParsingOptions {
            allow_dtd: true,
            ..Default::default()
        },
    ) {
        Ok(d) => d,
        Err(_) => return ptr::null_mut(),
    };

    // The document root element (skipping Document node itself)
    let root_node = doc.root_element();
    let root = build_node(root_node);

    Box::into_raw(Box::new(EmaneXmlDoc { root }))
}

#[no_mangle]
pub extern "C" fn emane_rs_xml_doc_free(doc: *mut EmaneXmlDoc) {
    if !doc.is_null() {
        unsafe {
            let d = Box::from_raw(doc);
            free_node(d.root);
        }
    }
}

#[no_mangle]
pub extern "C" fn emane_rs_xml_get_prop(
    node: *mut EmaneXmlNode,
    name: *const c_char,
) -> *mut c_char {
    if node.is_null() || name.is_null() {
        return ptr::null_mut();
    }
    let n = unsafe { CStr::from_ptr(name) };
    let mut attr = unsafe { (*node).attrs };
    while !attr.is_null() {
        let a = unsafe { &*attr };
        let a_name = unsafe { CStr::from_ptr(a.name) };
        if a_name == n {
            let value_str = unsafe { CStr::from_ptr(a.value).to_str().unwrap() };
            return CString::new(value_str).unwrap().into_raw();
        }
        attr = a.next;
    }
    ptr::null_mut()
}

#[no_mangle]
pub extern "C" fn emane_rs_xml_free_prop(prop: *mut c_char) {
    if !prop.is_null() {
        unsafe {
            drop(CString::from_raw(prop));
        }
    }
}
