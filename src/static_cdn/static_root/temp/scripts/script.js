
        document.addEventListener('DOMContenentLoaded', () => {
            const options = {
            chart : {
                type: 'column',
                zoomType: 'xy'
            },
            title : {
            text: 'column'
            
            },
            yAxis : {
            title : {
            text: 'column'
            
            }
            
            }
            };
            options.data = {
            csvURL: 'http://localhost/test/test.csv',
            enablePolling: true,
            dataRefreshRate: 2
            };
            Highcharts.chart('container', options);
            });