// Initialize the Cesium viewer
var viewer = new Cesium.Viewer('cesiumContainer');

// Function to add clickable names
function addClickableName(name, position) {
    // Add the entity (label) with the given name and position
    var labelEntity = viewer.entities.add({
        position: Cesium.Cartesian3.fromDegrees(position.lon, position.lat),
        label: {
            text: name,
            font: '18px sans-serif',
            fillColor: Cesium.Color.WHITE,
            outlineColor: Cesium.Color.BLACK,
            outlineWidth: 2,
            style: Cesium.LabelStyle.FILL_AND_OUTLINE,
            verticalOrigin: Cesium.VerticalOrigin.BOTTOM,
            heightReference: Cesium.HeightReference.CLAMP_TO_GROUND
        }
    });

    // Add a click event handler for the label
    viewer.screenSpaceEventHandler.setInputAction(function(click) {
        var pickedObject = viewer.scene.pick(click.position);
        if (Cesium.defined(pickedObject) && pickedObject.id === labelEntity) {
            alert('You clicked on ' + name);
        }
    }, Cesium.ScreenSpaceEventType.LEFT_CLICK);
}

// Example usage
addClickableName('Location A', { lon: -123.0744619, lat: 44.0503706 });
addClickableName('Location B', { lon: -122.0744619, lat: 43.0503706 });

