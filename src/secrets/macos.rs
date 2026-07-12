use crate::passwords;
use crate::secrets::{Secret, SecretError};
use objc2_core_foundation::*;
use objc2_security::*;

pub fn add(secret: &Secret) -> Result<(), SecretError> {
    if secret.value().is_empty() {
        return Err(SecretError::EmptyValue);
    }
    let name_ref = CFString::from_str(secret.name());
    let value_ref = CFData::from_bytes(secret.value().as_bytes());
    let dict = unsafe {
        CFMutableDictionary::new(
            None,
            0,
            &kCFTypeDictionaryKeyCallBacks,
            &kCFTypeDictionaryValueCallBacks,
        )
    }
    .ok_or_else(|| SecretError::PlatformError("Failed to create dictionary".to_string()))?;
    unsafe {
        dict.cast_unchecked::<CFString, CFString>()
            .add(kSecClass, kSecClassGenericPassword);
        dict.cast_unchecked::<CFString, CFString>()
            .add(kSecAttrService, name_ref.as_ref());
        dict.cast_unchecked::<CFString, CFData>()
            .add(kSecValueData, value_ref.as_ref());
        dict.cast_unchecked::<CFString, CFBoolean>().add(
            kSecAttrSynchronizable,
            kCFBooleanFalse.expect("Failed to get kCFBooleanFalse"),
        );
    }
    let status = unsafe { SecItemAdd(&dict, std::ptr::null_mut()) };
    if status == errSecDuplicateItem {
        return Err(SecretError::AlreadyExists);
    } else if status != errSecSuccess {
        return Err(SecretError::PlatformError("SecItemAdd failed".to_string()));
    }
    Ok(())
}

pub fn create_random(name: &str) -> Result<Secret, SecretError> {
    let generator = passwords::Generator::default();
    let secret = Secret::new(name.to_string(), generator.generate(64));
    match add(&secret) {
        Ok(_) => Ok(secret),
        Err(e) => Err(e),
    }
}

pub fn get(name: &str) -> Result<Secret, SecretError> {
    let name_ref = CFString::from_str(name);
    let dict = unsafe {
        CFMutableDictionary::new(
            None,
            0,
            &kCFTypeDictionaryKeyCallBacks,
            &kCFTypeDictionaryValueCallBacks,
        )
    }
    .ok_or_else(|| SecretError::PlatformError("Failed to create dictionary".to_string()))?;
    unsafe {
        dict.cast_unchecked::<CFString, CFString>()
            .add(kSecClass, kSecClassGenericPassword);
        dict.cast_unchecked::<CFString, CFString>()
            .add(kSecAttrService, name_ref.as_ref());
        dict.cast_unchecked::<CFString, CFString>()
            .add(kSecMatchLimit, kSecMatchLimitOne);
        dict.cast_unchecked::<CFString, CFBoolean>().add(
            kSecReturnData,
            kCFBooleanTrue.expect("Failed to get kCFBooleanTrue"),
        );
    }
    let mut result: *const CFType = std::ptr::null();
    let status = unsafe { SecItemCopyMatching(&dict, &mut result) };
    if status == errSecItemNotFound {
        return Err(SecretError::NotFound);
    } else if status != errSecSuccess || result.is_null() {
        return Err(SecretError::PlatformError(
            "SecItemCopyMatching failed".to_string(),
        ));
    }
    let owned =
        unsafe { CFRetained::from_raw(std::ptr::NonNull::new(result as *mut CFType).unwrap()) };
    let data = unsafe { CFRetained::cast_unchecked::<CFData>(owned) };
    let value = unsafe { std::slice::from_raw_parts(data.byte_ptr(), data.len()).to_vec() };
    return Ok(Secret {
        name: name.to_string(),
        value: String::from_utf8(value).map_err(|_| {
            SecretError::PlatformError("Failed to convert secret value to UTF-8".to_string())
        })?,
    });
}

pub fn remove(name: &str) -> Result<(), SecretError> {
    let name_ref = CFString::from_str(name);
    let dict = unsafe {
        CFMutableDictionary::new(
            None,
            0,
            &kCFTypeDictionaryKeyCallBacks,
            &kCFTypeDictionaryValueCallBacks,
        )
    }
    .ok_or_else(|| SecretError::PlatformError("Failed to create dictionary".to_string()))?;
    unsafe {
        dict.cast_unchecked::<CFString, CFString>()
            .add(kSecClass, kSecClassGenericPassword);
        dict.cast_unchecked::<CFString, CFString>()
            .add(kSecAttrService, name_ref.as_ref());
    }
    let status = unsafe { SecItemDelete(&dict) };
    if status == errSecItemNotFound {
        return Err(SecretError::NotFound);
    } else if status != errSecSuccess {
        return Err(SecretError::PlatformError(
            "SecItemDelete failed".to_string(),
        ));
    }
    Ok(())
}

pub fn update(secret: &Secret) -> Result<(), SecretError> {
    if secret.value().is_empty() {
        return Err(SecretError::EmptyValue);
    }
    let name_ref = CFString::from_str(secret.name());
    let value_ref = CFData::from_bytes(secret.value().as_bytes());
    let query_dict = unsafe {
        CFMutableDictionary::new(
            None,
            0,
            &kCFTypeDictionaryKeyCallBacks,
            &kCFTypeDictionaryValueCallBacks,
        )
    }
    .ok_or_else(|| SecretError::PlatformError("Failed to create dictionary".to_string()))?;
    unsafe {
        query_dict
            .cast_unchecked::<CFString, CFString>()
            .add(kSecClass, kSecClassGenericPassword);
        query_dict
            .cast_unchecked::<CFString, CFString>()
            .add(kSecAttrService, name_ref.as_ref());
    }
    let attr_dict = unsafe {
        CFMutableDictionary::new(
            None,
            0,
            &kCFTypeDictionaryKeyCallBacks,
            &kCFTypeDictionaryValueCallBacks,
        )
    }
    .ok_or_else(|| SecretError::PlatformError("Failed to create dictionary".to_string()))?;
    unsafe {
        attr_dict
            .cast_unchecked::<CFString, CFData>()
            .add(kSecValueData, value_ref.as_ref());
    }
    let status = unsafe { SecItemUpdate(&query_dict, &attr_dict) };
    if status == errSecItemNotFound {
        return Err(SecretError::NotFound);
    } else if status != errSecSuccess {
        return Err(SecretError::PlatformError(
            "SecItemUpdate failed".to_string(),
        ));
    }
    Ok(())
}

pub fn upsert(secret: &Secret) -> Result<(), SecretError> {
    match update(secret) {
        Ok(_) => Ok(()),
        Err(SecretError::NotFound) => add(secret),
        Err(e) => Err(e),
    }
}
