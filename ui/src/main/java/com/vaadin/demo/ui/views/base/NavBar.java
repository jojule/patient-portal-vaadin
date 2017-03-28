package com.vaadin.demo.ui.views.base;

import com.vaadin.ui.Button;
import com.vaadin.ui.HorizontalLayout;

import java.util.LinkedHashMap;
import java.util.Map;

public class NavBar extends HorizontalLayout {
    protected Map<String, Button> navButtons = new LinkedHashMap<>();

}
