const { createHash, timingSafeEqual } = require("crypto");
const got = require("got");

class Paycek {
	constructor({ apiKey, apiSecret }) {
		this.apiKey = apiKey;
		this.apiSecret = apiSecret;
		this.apiHost = "https://paycek.io";
		this.apiPrefix = "/processing/api";
		this.encoding = "utf-8";
	}

	#generateMacHash(nonceString, endpoint, bodyBytes, httpMethod = "POST", contentType = "application/json") {
		const hash = createHash("sha3-512");
		hash.update(`\0`);
		hash.update(Buffer.from(this.apiKey, this.encoding));
		hash.update(`\0`);
		hash.update(Buffer.from(this.apiSecret, this.encoding));
		hash.update(`\0`);
		hash.update(Buffer.from(nonceString, this.encoding));
		hash.update(`\0`);
		hash.update(Buffer.from(httpMethod, this.encoding));
		hash.update(`\0`);
		hash.update(Buffer.from(endpoint, this.encoding));
		hash.update(`\0`);
		hash.update(Buffer.from(contentType, this.encoding));
		hash.update(`\0`);
		hash.update(bodyBytes);
		hash.update(`\0`);

		return hash.digest("hex");
	}

	#apiCall(endpoint, body) {
		const prefixedEndpoint = `${this.apiPrefix}/${endpoint}`;
		const bodyBytes = Buffer.from(JSON.stringify(body), this.encoding);
		const nonceString = new Date().getTime().toString();

		const macHash = this.#generateMacHash(nonceString, prefixedEndpoint, bodyBytes);

		const headers = {
			"Content-Type": "application/json",
			"ApiKeyAuth-Key": this.apiKey,
			"ApiKeyAuth-Nonce": nonceString,
			"ApiKeyAuth-MAC": macHash
		};

		const options = {
			method: "POST",
			responseType: "json",
			headers: headers,
			body: bodyBytes
		};

		return got.post(this.apiHost + prefixedEndpoint, options);
	}

	/**
	 * This method is used to verify callback was encoded by paycek.
	 * A mac digest will be created by encoding nonce from headers, endpoint, body bytes, your api key and secret, http method and content type.
	 * That value will be compared with mac digest from headers.
	 *
	 * @param {Object} headers: callback headers
	 * @param {string} endpoint: callback endpoint
	 * @param {bytes} bodyBytes: callback body bytes
	 * @param {string} httpMethod: callback http method
	 * @param {string} contentType: callback content type
	 * @return {bool} true if the generated mac digest is equal to the one received in headers, false otherwise
	 */
	checkHeaders({ headers, endpoint, bodyBytes, httpMethod = "GET", contentType = "" }) {
		try {
			const headersLower = Object.fromEntries(Object.keys(headers).map((key) => [key.toLowerCase(), headers[key]]));
			const generatedMac = this.#generateMacHash(headersLower["apikeyauth-nonce"], endpoint, bodyBytes, httpMethod, contentType);

			return timingSafeEqual(Buffer.from(generatedMac, this.encoding), Buffer.from(headersLower["apikeyauth-mac"], this.encoding));
		} catch (error) {
			return false;
		}
	}

	/**
	 *  @param optionalFields: Optional fields:
	 *       payment_id: string
	 *       location_id: string
	 *       items: array
	 *       email: string
	 *       success_url: string
	 *       fail_url: string
	 *       back_url: string
	 *       success_url_callback: string
	 *       fail_url_callback: string
	 *       status_url_callback: string
	 *       description: string
	 *       language: string
	 *       generate_pdf: bool
	 *       client_fields: Object
	 */
	generatePaymentUrl({ profileCode, dstAmount, ...optionalFields }) {
		return this.openPayment({ profileCode, dstAmount, ...optionalFields })
			.then((response) => {
				try {
					return response.body.data.payment_url;
				} catch (error) {
					throw error;
				}
			})
			.catch((error) => {
				throw error;
			});
	}

	getPayment({ paymentCode }) {
		const body = {
			payment_code: paymentCode
		};

		return this.#apiCall("payment/get", body);
	}

	/**
	 * You can implement getting payment status in 3 ways:
	 * 1. **Provide `status_url_callback`** upon opening a payment and receive status updates on your endpoint.
	 * 2. **Provide `success_url_callback` and `fail_url_callback`** upon opening a payment and receive success and fail updates on your endpoints.
	 * 3. **Manually poll `payment/get`** to check payment status.
	 *
	 * **Do not use `fail_url` and `success_url` to update payment status in your system. These URLs are used ONLY for redirecting users back to your shop.**
	 *
	 * **Authorization**
	 *
	 * If you decide to use callbacks, you **must check the headers for every callback** to ensure they are authorized.
	 * If a callback doesn't have a valid Authorization header, your server must respond with a **401 Unauthorized** status. If the callback has a valid Authorization header, your server must respond with a **200 OK** status.
	 *
	 * **Integration Testing**
	 *
	 * In order to ensure system security, on every new payment, an automated integration test will check if your integration is secure.
	 * An API call with an invalid Authorization header will be made to each of your callback endpoints. If any endpoint returns a status other than 401 for requests with an invalid Authorization header, **all ongoing payments will be canceled**, and your **profile will be blocked** to prevent unauthorized transactions. Ensure your endpoints are correctly configured to handle authorization and respond appropriately.
	 *
	 * *Test profiles won't be blocked even if the response for callbacks with an invalid Authorization header returns an invalid status. The payment will still be canceled.*
	 *
	 * @param {string} profileCode - The profile code for the payment.
	 * @param {number} dstAmount - The amount of the payment.
	 * @param [optionalFields] - Optional fields.
	 *   -  payment_id: string
	 *   - location_id: string
	 *   - items: array
	 *   - email: string
	 *   - success_url: string
	 *   - fail_url: string
	 *   - back_url: string
	 *   - success_url_callback: string
	 *   - fail_url_callback: string
	 *   - status_url_callback: string
	 *   - description: string
	 *   - language: string
	 *   - generate_pdf: bool
	 *   - client_fields: Object
	 */
	openPayment({ profileCode, dstAmount, ...optionalFields }) {
		const body = {
			profile_code: profileCode,
			dst_amount: dstAmount,
			...optionalFields
		};

		return this.#apiCall("payment/open", body);
	}

	/**
	 *  @param optionalFields: Optional fields:
	 *       src_protocol: string
	 */
	updatePayment({ paymentCode, srcCurrency, ...optionalFields }) {
		const body = {
			payment_code: paymentCode,
			src_currency: srcCurrency,
			...optionalFields
		};

		return this.#apiCall("payment/update", body);
	}

	cancelPayment({ paymentCode }) {
		const body = {
			payment_code: paymentCode
		};

		return this.#apiCall("payment/cancel", body);
	}

	getProfileInfo({ profileCode }) {
		const body = {
			profile_code: profileCode
		};

		return this.#apiCall("profile_info/get", body);
	}

	/**
	 *  @param {Object} details: Withdraw details object with fields:
	 *			iban: string (required)
	 *			purpose: string
	 *			model: string
	 *			pnb: string
	 *  @param optionalFields: Optional fields:
	 *			id: string
	 */
	profileWithdraw({ profileCode, method, amount, details, ...optionalFields }) {
		const body = {
			profile_code: profileCode,
			method: method,
			amount: amount,
			details: details,
			...optionalFields
		};

		return this.#apiCall("profile/withdraw", body);
	}

	/**
	 *  @param {Object} profileAutomaticWithdrawDetails: Automatic withdraw details object with fields:
	 *			iban: string (required)
	 *			purpose: string
	 *			model: string
	 *			pnb: string
	 *  @param optionalFields: Optional fields:
	 *			type: string
	 *			oib: string
	 *			vat: string
	 *			profile_name: string
	 *			profile_email: string
	 *			profile_type: string
	 */
	createAccount({ email, name, street, city, country, profileCurrency, profileAutomaticWithdrawMethod, profileAutomaticWithdrawDetails, ...optionalFields }) {
		const body = {
			email: email,
			name: name,
			street: street,
			city: city,
			country: country,
			profile_currency: profileCurrency,
			profile_automatic_withdraw_method: profileAutomaticWithdrawMethod,
			profile_automatic_withdraw_details: profileAutomaticWithdrawDetails,
			...optionalFields
		};

		return this.#apiCall("account/create", body);
	}

	/**
	 *  @param {Object} profileAutomaticWithdrawDetails: Automatic withdraw details object with fields:
	 *			iban: string (required)
	 *			purpose: string
	 *			model: string
	 *			pnb: string
	 *  @param optionalFields: Optional fields:
	 *			type: string
	 *			oib: string
	 *			vat: string
	 *			profile_name: string
	 *			profile_email: string
	 */
	createAccountWithPassword({ email, password, name, street, city, country, profileCurrency, profileAutomaticWithdrawMethod, profileAutomaticWithdrawDetails, ...optionalFields }) {
		const body = {
			email: email,
			password: password,
			name: name,
			street: street,
			city: city,
			country: country,
			profile_currency: profileCurrency,
			profile_automatic_withdraw_method: profileAutomaticWithdrawMethod,
			profile_automatic_withdraw_details: profileAutomaticWithdrawDetails,
			...optionalFields
		};

		return this.#apiCall("account/create_with_password", body);
	}

	/**
	 *  @param optionalFields: Optional fields:
	 *			location_id: string
	 */
	getReports({ profileCode, datetimeFrom, datetimeTo, ...optionalFields }) {
		const body = {
			profile_code: profileCode,
			datetime_from: datetimeFrom,
			datetime_to: datetimeTo,
			...optionalFields
		};

		return this.#apiCall("reports/get", body);
	}
}

module.exports = Paycek;
