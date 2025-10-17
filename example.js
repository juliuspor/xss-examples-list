/**
 * 
 * SOURCES:
 * - jQuery .data() reads
 * - jQuery .attr()/.prop() reads
 * - jQuery .text() reads
 * - jQuery .html() reads
 * - dataset field access
 * - AJAX response data
 * - jQuery .val() reads
 * - Form attribute reads
 * 
 * SINKS:
 * - innerHTML/outerHTML assignments
 * - jQuery .html() writes
 * - jQuery .replaceWith()
 * - eval()
 * - document.write()/writeln()
 * - Event handler attributes (onclick, onload, etc.)
 * - Dangerous attributes (href, src, action)
 */

// ============================================================================
// PATTERN 1: jQuery .data() -> innerHTML
// ============================================================================
function vulnerableDataToInnerHTML() {
    const userInput = $('#user-input').data('value');
    document.getElementById('output').innerHTML = userInput;  // SINK: innerHTML
}

// ============================================================================
// PATTERN 2: jQuery .data(key) -> jQuery .html()
// ============================================================================
function vulnerableDataKeyToHtml() {
    const userData = $(this).data('user-content');
    $('#result').html(userData);  // SINK: jQuery html() write
}

// ============================================================================
// PATTERN 3: jQuery .attr() read -> outerHTML
// ============================================================================
function vulnerableAttrToOuterHTML() {
    const linkUrl = $('#malicious-link').attr('data-url');
    document.getElementById('container').outerHTML = linkUrl;  // SINK: outerHTML
}

// ============================================================================
// PATTERN 4: jQuery .prop() read -> jQuery .html()
// ============================================================================
function vulnerablePropToHtml() {
    const propValue = $('input').prop('value');
    $('.output').html(propValue);  // SINK: jQuery html()
}

// ============================================================================
// PATTERN 5: jQuery .text() read -> innerHTML
// ============================================================================
function vulnerableTextToInnerHTML() {
    const textContent = $('#source').text();
    document.getElementById('target').innerHTML = textContent;  // SINK: innerHTML
}



