package com.vaadin.demo.ui.views.analytics;

import com.vaadin.addon.charts.Chart;
import com.vaadin.addon.charts.model.AxisType;
import com.vaadin.addon.charts.model.ChartType;
import com.vaadin.addon.charts.model.DataSeries;
import com.vaadin.addon.charts.model.DataSeriesItem;
import com.vaadin.demo.service.AnalyticsService;
import com.vaadin.demo.service.StringLongPair;
import com.vaadin.navigator.View;
import com.vaadin.navigator.ViewChangeListener;
import com.vaadin.server.Page;
import com.vaadin.spring.annotation.SpringComponent;
import com.vaadin.spring.annotation.SpringView;
import com.vaadin.ui.Layout;
import com.vaadin.ui.TabSheet;
import com.vaadin.ui.VerticalLayout;
import com.vaadin.ui.themes.ValoTheme;
import org.springframework.beans.factory.annotation.Autowired;

import javax.annotation.PostConstruct;
import java.util.Comparator;
import java.util.List;

@SpringComponent
@SpringView
public class AnalyticsView extends VerticalLayout implements View {

    @Autowired
    private AnalyticsService service;
    private TabSheet tabSheet;

    @Override
    public void enter(ViewChangeListener.ViewChangeEvent event) {
        Page.getCurrent().setTitle("Analytics");
        String parameters = event.getParameters();
        if (!parameters.isEmpty()) {
            tabSheet.iterator().forEachRemaining(t -> {
                if (t.getCaption().toLowerCase().equals(parameters)) {
                    tabSheet.setSelectedTab(t);
                }
            });
        }
    }

    @PostConstruct
    void init() {
        tabSheet = new TabSheet();
        tabSheet.setStyleName(ValoTheme.TABSHEET_CENTERED_TABS);
        tabSheet.addStyleName("detail-tabs");
        addComponent(tabSheet);

        tabSheet.addTab(getAgeChart());
        tabSheet.addTab(getGenderChart());
        tabSheet.addTab(getDoctorChart());

        addComponentsAndExpand(tabSheet);

        tabSheet.addSelectedTabChangeListener(tabChanged -> {
            String caption = tabSheet.getSelectedTab().getCaption().toLowerCase();
            Page.getCurrent().setUriFragment("!analytics/" + caption, false);
        });
    }

    private Layout getAgeChart() {
        List<StringLongPair> data = service.getStatsByAge();
        data.sort(Comparator.comparing(StringLongPair::getGroup));

        return getChart("Patients bt Age", data, "Age");
    }

    private Layout getGenderChart() {
        return getChart("Gender", service.getStatsByGender(), "Gender");
    }

    private Layout getDoctorChart() {

        return getChart("Patients per Doctor", service.getStatsByDoctor(), "Doctor");
    }

    private Layout getChart(String title, List<StringLongPair> data, String caption) {
        Chart chart = new Chart(ChartType.COLUMN);
        chart.getConfiguration().setTitle(title);
        DataSeries ds = new DataSeries();
        data.forEach(d -> ds.add(new DataSeriesItem(d.getGroup(), d.getCount())));
        chart.getConfiguration().addSeries(ds);
        chart.getConfiguration().getxAxis().setType(AxisType.CATEGORY);

        VerticalLayout layout = new VerticalLayout(chart);
        layout.setCaption(caption);
        return layout;
    }
}
