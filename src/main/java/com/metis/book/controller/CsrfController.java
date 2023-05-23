package com.metis.book.controller;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.servlet.ModelAndView;

@RestController
@RequestMapping("/demo-web")
public class CsrfController {

	@GetMapping
	public ModelAndView getDemoCSRFPage(ModelAndView mv) {
		mv.setViewName("/csrf/csrf_demo.html");
		return mv;
	}
}
