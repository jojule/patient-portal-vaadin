package com.vaadin.demo.ui.converters;

import com.vaadin.data.Converter;
import com.vaadin.data.Result;
import com.vaadin.data.ValueContext;

import java.time.LocalDate;
import java.time.ZoneId;
import java.util.Date;

public class DateConverter implements Converter<LocalDate, Date> {

    @Override
    public Result<Date> convertToModel(LocalDate value, ValueContext context) {
        return Result.ok(Date.from(value.atStartOfDay(ZoneId.systemDefault()).toInstant()));
    }

    @Override
    public LocalDate convertToPresentation(Date value, ValueContext context) {
        return new Date(value.getTime()).toInstant().atZone(ZoneId.systemDefault()).toLocalDate();
    }
}
