package com.vaadin.demo.ui.mobile;

import com.vaadin.server.FontAwesome;
import com.vaadin.ui.*;
import com.vaadin.ui.ComboBox;
import com.vaadin.ui.themes.ValoTheme;
import com.vaadin.ui.HorizontalLayout;
import com.vaadin.ui.Label;
import com.vaadin.ui.VerticalLayout;
import org.apache.commons.lang3.StringUtils;

/**
 * Created by mstahv
 */
public abstract class MobileListing<T> extends VerticalLayout {
    private Label sortTitle = new Label("SORT BY:");
    private ComboBox<String> sortPropertySelect = new ComboBox<>();
    private Button addBtn = new Button("", FontAwesome.PLUS);
    private Button loadMoreBtn = new Button("Load more...", e -> loadMore());

    protected abstract void loadMore();

    public abstract void list();

    protected abstract void onAdd();

    private CssLayout results = new CssLayout();

    protected MobileListing(Class<T> type) {
        results.addStyleName("data-layout");

        addBtn.addClickListener(e -> onAdd());
        addBtn.addStyleName(ValoTheme.BUTTON_BORDERLESS);

        sortPropertySelect.setWidth("100%");

        HorizontalLayout layout = new HorizontalLayout(sortTitle, sortPropertySelect, addBtn);
        layout.setComponentAlignment(sortTitle, Alignment.MIDDLE_LEFT);
        layout.setWidth("100%");
        layout.setExpandRatio(sortPropertySelect, 1);
        layout.addStyleName("search-bar");

        addComponent(layout);
        addComponent(results);
        addComponent(loadMoreBtn);

        loadMoreBtn.setEnabled(false);
        loadMoreBtn.setWidth("100%");
    }

    protected int count() {
        return results.getComponentCount();
    }

    protected void clear() {
        results.removeAllComponents();
    }

    protected void addRow(MobileRow r) {
        results.addComponent(r);
    }

    protected void setSortProperties(String... props) {
        sortPropertySelect.setItems(props);
        sortPropertySelect.setValue(props[0]);
        sortPropertySelect.setItemCaptionGenerator(s -> {
            String str = StringUtils.join(StringUtils.splitByCharacterTypeCamelCase(s), " ");
            if (str.contains(".")) {
                str = str.substring(0, str.indexOf("."));
            }
            return StringUtils.capitalize(str);
        });
        sortPropertySelect.addValueChangeListener(e -> list());
    }

    protected String getSortProperty() {
        return sortPropertySelect.getValue();
    }

    protected void setLoadMoreEnabled(boolean b) {
        loadMoreBtn.setEnabled(b);
    }


}
