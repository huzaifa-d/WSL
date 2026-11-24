set(WSLC_ACI_INCLUDE_DIR ${CMAKE_CURRENT_SOURCE_DIR}/include)

add_library(wslc_aci_client STATIC
    ${CMAKE_SOURCE_DIR}/src/windows/common/wslc/services/WslcAciClient.cpp
    ${CMAKE_SOURCE_DIR}/src/windows/common/wslc/services/WslcAciClient.h)
target_include_directories(wslc_aci_client PUBLIC ${WSLC_ACI_INCLUDE_DIR})
target_link_libraries(wslc_aci_client PUBLIC common ${COMMON_LINK_LIBRARIES})
target_precompile_headers(wslc_aci_client REUSE_FROM common)
add_dependencies(wslc_aci_client wslserviceidl)
set_target_properties(wslc_aci_client PROPERTIES FOLDER windows)

if (TARGET_PLATFORM STREQUAL "x64")
    find_program(WSLC_ACI_CARGO cargo REQUIRED)
    set(WSLC_ACI_MANIFEST ${CMAKE_CURRENT_SOURCE_DIR}/Cargo.toml)
    set(WSLC_ACI_TARGET x86_64-pc-windows-msvc)
    if (CMAKE_BUILD_TYPE STREQUAL "Debug")
        set(WSLC_ACI_PROFILE debug)
        set(WSLC_ACI_RELEASE_FLAG)
    else()
        set(WSLC_ACI_PROFILE release)
        set(WSLC_ACI_RELEASE_FLAG --release)
    endif()

    file(GLOB_RECURSE WSLC_ACI_RUST_SOURCES CONFIGURE_DEPENDS ${CMAKE_CURRENT_SOURCE_DIR}/src/*.rs)
    set(WSLC_ACI_TRANSLATOR_DIR ${CMAKE_CURRENT_BINARY_DIR}/translator)
    set(WSLC_ACI_AGENT_DIR ${CMAKE_CURRENT_BINARY_DIR}/agent)
    set(WSLC_ACI_TRANSLATOR_LIB ${WSLC_ACI_TRANSLATOR_DIR}/${WSLC_ACI_TARGET}/${WSLC_ACI_PROFILE}/wslc_aci_bridge.lib)
    set(WSLC_ACI_AGENT_LIB ${WSLC_ACI_AGENT_DIR}/${WSLC_ACI_TARGET}/${WSLC_ACI_PROFILE}/wslc_aci_bridge.lib)
    set(WSLC_ACI_STAGED_BUNDLE ${CMAKE_RUNTIME_OUTPUT_DIRECTORY}/${CMAKE_BUILD_TYPE}/aci-edge-sandboxes)

    add_custom_command(
        OUTPUT ${WSLC_ACI_TRANSLATOR_LIB}
        COMMAND ${CMAKE_COMMAND} -E env CARGO_TARGET_DIR=${WSLC_ACI_TRANSLATOR_DIR}
                ${WSLC_ACI_CARGO} build --locked --manifest-path ${WSLC_ACI_MANIFEST}
                --target ${WSLC_ACI_TARGET} --no-default-features --features translator ${WSLC_ACI_RELEASE_FLAG}
        DEPENDS ${WSLC_ACI_MANIFEST} ${CMAKE_CURRENT_SOURCE_DIR}/Cargo.lock ${WSLC_ACI_RUST_SOURCES}
        VERBATIM)
    add_custom_target(wslc_aci_translator_build DEPENDS ${WSLC_ACI_TRANSLATOR_LIB})
    add_library(wslc_aci_translator STATIC IMPORTED GLOBAL)
    set_target_properties(wslc_aci_translator PROPERTIES IMPORTED_LOCATION ${WSLC_ACI_TRANSLATOR_LIB})
    add_dependencies(wslc_aci_translator wslc_aci_translator_build)

    add_custom_command(
        OUTPUT ${WSLC_ACI_AGENT_LIB} ${WSLC_ACI_STAGED_BUNDLE}/SOURCE-MANIFEST.json
        COMMAND ${CMAKE_COMMAND} -E env CARGO_TARGET_DIR=${WSLC_ACI_AGENT_DIR}
                ${WSLC_ACI_CARGO} build --locked --manifest-path ${WSLC_ACI_MANIFEST}
                --target ${WSLC_ACI_TARGET} --no-default-features --features agent ${WSLC_ACI_RELEASE_FLAG}
        COMMAND ${CMAKE_COMMAND} -E make_directory ${WSLC_ACI_STAGED_BUNDLE}
        COMMAND ${CMAKE_COMMAND} -E copy_directory
                ${WSLC_ACI_AGENT_DIR}/${WSLC_ACI_TARGET}/${WSLC_ACI_PROFILE}/aci-edge-sandboxes
                ${WSLC_ACI_STAGED_BUNDLE}
        DEPENDS ${WSLC_ACI_MANIFEST} ${CMAKE_CURRENT_SOURCE_DIR}/Cargo.lock ${WSLC_ACI_RUST_SOURCES}
        VERBATIM)
    add_custom_target(wslc_aci_agent_build DEPENDS ${WSLC_ACI_AGENT_LIB} ${WSLC_ACI_STAGED_BUNDLE}/SOURCE-MANIFEST.json)
    add_library(wslc_aci_agent STATIC IMPORTED GLOBAL)
    set_target_properties(wslc_aci_agent PROPERTIES IMPORTED_LOCATION ${WSLC_ACI_AGENT_LIB})
    add_dependencies(wslc_aci_agent wslc_aci_agent_build)

    set(WSLC_ACI_NATIVE_LIBS ntdll bcrypt advapi32 rpcrt4 OneCore_apiset kernel32 userenv ws2_32 dbghelp)
    target_link_libraries(wslc_aci_agent INTERFACE ${WSLC_ACI_NATIVE_LIBS})
    target_link_libraries(wslc_aci_client PUBLIC wslc_aci_translator ${WSLC_ACI_NATIVE_LIBS})
    add_dependencies(wslc_aci_client wslc_aci_translator_build)
endif()
