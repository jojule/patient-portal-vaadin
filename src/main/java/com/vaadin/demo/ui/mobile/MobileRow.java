package com.vaadin.demo.ui.mobile;

import com.vaadin.server.FontAwesome;
import com.vaadin.shared.ui.MarginInfo;
import com.vaadin.shared.ui.label.ContentMode;
import com.vaadin.ui.Alignment;
import com.vaadin.ui.Button;
import com.vaadin.ui.FormLayout;
import com.vaadin.ui.HorizontalLayout;
import com.vaadin.ui.Label;
import com.vaadin.ui.VerticalLayout;
import com.vaadin.ui.themes.ValoTheme;

/**
 * Created by mstahv
 */
abstract class MobileRow extends VerticalLayout {

    protected final HorizontalLayout header;

    private Button selectBtn;
    private Label carret = new Label();
    protected Label title = new Label();
    protected Label desc = new Label();
    private FormLayout details = new FormLayout();

    private boolean detailsExpanded = false;

    public MobileRow(String titleStr, String descStr) {
        super();
        setMargin(false);

        header = new HorizontalLayout(carret, title, desc);
        // Align all or set default alignment would be nice to have
        header.setComponentAlignment(carret, Alignment.MIDDLE_LEFT);
        header.setComponentAlignment(title, Alignment.MIDDLE_LEFT);
        header.setComponentAlignment(desc, Alignment.MIDDLE_LEFT);
        header.setMargin(new MarginInfo(false, true, false, true));
        header.setWidth("100%");
        header.setExpandRatio(title, 1);
        addComponent(header);

        // Set icon sets the icon into the caption also for label so
        // we need to use the combination ContentMode.HTML + Icon.getHtml()
        carret.setContentMode(ContentMode.HTML);
        carret.setValue(FontAwesome.CARET_RIGHT.getHtml());

        title.setValue(titleStr);

        desc.setValue(descStr);
        addComponent(details);

        details.setVisible(false);
        details.addStyleName("mobile-detail");
        details.setMargin(false);

        header.addLayoutClickListener(e -> {
            showDetails(detailsExpanded = !detailsExpanded);
            setStyleName("open", detailsExpanded);
            carret.setValue(detailsExpanded ? FontAwesome.CARET_DOWN.getHtml() : FontAwesome.CARET_RIGHT.getHtml());
            details.setVisible(detailsExpanded);
        });
    }

    public void addSelectClickListener(Button.ClickListener listener) {
        selectBtn = new Button(FontAwesome.ARROW_RIGHT);
        selectBtn.addStyleName(ValoTheme.BUTTON_BORDERLESS);
        selectBtn.addStyleName(ValoTheme.BUTTON_ICON_ONLY);

        header.addComponent(selectBtn);
        selectBtn.addClickListener(listener);
    }

    public HorizontalLayout getHeader() {
        return header;
    }

    protected void showDetail(String name, Object value) {
        Label label = new Label(value.toString());
        label.setCaption(name.toUpperCase());
        details.addComponent(label);
    }

    protected abstract void showDetails(boolean expanded);

    protected void clear() {
        details.removeAllComponents();
    }

}