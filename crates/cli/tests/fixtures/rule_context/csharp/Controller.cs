using System;
using Microsoft.AspNetCore.Mvc;
public class ReviewController : Controller {
    public IActionResult Direct([FromQuery] string next) {
        return Redirect(next);
    }
    public void Encoded([FromQuery] string next) {
        Response.Redirect(Uri.EscapeUriString(next));
    }
    public void ResponseControl([FromQuery] string next) {
        Response.Redirect(next);
    }
}
