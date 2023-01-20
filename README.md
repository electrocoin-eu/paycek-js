# Paycek

This is an official package for the [Paycek crypto payment processor](https://paycek.io). The documentation provided in code explains only minor implementation details.

For in depth information about endpoints, fields and more, read our [API Documentation](https://paycek.io/api/docs).

## Quick Start

### Installation

Install package with npm.

```shell
npm install paycek
```

### Initialization

Under account settings you’ll find your API key and secret. Initialize a paycek instance.

```javascript
const Paycek = require('paycek');

const paycek = new Paycek('<apiKey>', '<apiSecret>');
```

### Usage


#### Get payment
```javascript
const payment = await paycek.getPayment({
    paymentCode: '<paymentCode>'
});
```

#### Open payment
```javascript
const payment = await paycek.openPayment({
    profileCode: '<profileCode>',
    dstAmount: '<dstAmount>',
    location_id: '<locationId>'
});
```