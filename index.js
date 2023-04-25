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
		const headersLower = Object.fromEntries(Object.keys(headers).map((key) => [key.toLowerCase(), headers[key]]));
		const generatedMac = this.#generateMacHash(headersLower["apikeyauth-nonce"], endpoint, bodyBytes, httpMethod, contentType);

		return timingSafeEqual(Buffer.from(generatedMac, this.encoding), Buffer.from(headersLower["apikeyauth-mac"], this.encoding));
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
