/* eslint-disable */
export const displayMap = (locations) => {
  mapboxgl.accessToken =
    'pk.eyJ1IjoibGVlaGl0IiwiYSI6ImNsa21hMnBiMjA2bWgzZG1peWxpcTBncnEifQ.t9HjhzKNWLSaCY75aM6_gw';

  const map = new mapboxgl.Map({
    container: 'map', // container ID
    style: 'mapbox://styles/leehit/clkniljik00jc01qphmw09wn3', // style URL
    scrollZoom: false,
    // center: [-80.185942, 25.774772], // starting position [lng, lat]
    // zoom: 9, // starting zoom
    // interactive: false,
  });

  const bounds = new mapboxgl.LngLatBounds();

  locations.forEach((loc) => {
    // Create maker
    const el = document.createElement('div');
    el.className = 'marker';

    // Add maker
    new mapboxgl.Marker({
      element: el,
      anchor: 'bottom',
    })
      .setLngLat(loc.coordinates)
      .addTo(map);

    // Add popup
    new mapboxgl.Popup({
      offset: [0, -15],
    })
      .setLngLat(loc.coordinates)
      .setHTML(`<p>Day ${loc.day}: ${loc.description}</p>`)
      .addTo(map);

    // Extend map bounds to include current locations
    bounds.extend(loc.coordinates);
  });

  map.fitBounds(bounds, {
    padding: {
      top: 100,
      bottom: 150,
      left: 100,
      right: 100,
    },
  });
};
