const { createHash } = require("crypto");
const got = require("got");

class Paycek {
	constructor({ apiKey, apiSecret }) {
		this.apiKey = apiKey;
		this.apiSecret = apiSecret;
		this.apiHost = "https://paycek.io";
		this.apiPrefix = "/processing/api";
		this.encoding = "utf-8";
	}

	#generateMacHash(nonceString, endpoint, bodyString, httpMethod = "POST", contentType = "application/json") {
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
		hash.update(Buffer.from(bodyString, this.encoding));
		hash.update(`\0`);

		return hash.digest("hex");
	}

	#apiCall(endpoint, body) {
		const prefixedEndpoint = `${this.apiPrefix}/${endpoint}`;
		const bodyString = JSON.stringify(body);
		const nonceString = new Date().getTime().toString();

		const macHash = this.#generateMacHash(nonceString, prefixedEndpoint, bodyString);

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
			body: Buffer.from(bodyString, this.encoding)
		};

		return got
			.post(this.apiHost + prefixedEndpoint, options)
			.then(function (result) {
				return result;
			})
			.catch(function (error) {
				return error;
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

	updatePayment({ paymentCode, srcCurrency }) {
		const body = {
			payment_code: paymentCode,
			src_currency: srcCurrency
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
	 *  @param details: Withdraw details object with fields:
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
	 *  @param profileAutomaticWithdrawDetails: Automatic withdraw details object with fields:
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
	 *  @param profileAutomaticWithdrawDetails: Automatic withdraw details object with fields:
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
