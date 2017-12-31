$(function(){

  // Initalize the ToC if we're on an article page
  if ($('#toc').length) {
    var toc = $('#toc');
    var tocOffset = toc.offset().top;
    var tocPadding = 20;

    var didScroll = true;
    $(window).scroll(function() {
      didScroll = true;
    })

    setInterval(function() {
      if (didScroll) {
        didScroll = false;

        if (window.scrollY > tocOffset - tocPadding)
          toc.addClass('sticky');
        else
          toc.removeClass('sticky');
      }
    }, 100);

  }
})

var reTocHash = /SCS\d{4}/;

function tocifyHasher (text, element)
{
    var match = reTocHash.exec(text);
    if (match == null)
        return text.replace(/\s/g, "");
    else
        return match[0];
}