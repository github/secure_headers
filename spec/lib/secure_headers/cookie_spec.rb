require 'spec_helper'

module SecureHeaders
  describe Cookie do
    let(:raw_cookie) { "_session=thisisatest" }

    it "does not tamper with cookies when unconfigured" do
      cookie = Cookie.new(raw_cookie, {})
      expect(cookie.to_s).to eq(raw_cookie)
    end

    it "flags secure cookies" do
      cookie = Cookie.new(raw_cookie, secure: true)
      expect(cookie.to_s).to match(Cookie::SECURE_REGEXP)
    end

    it "flags HttpOnly cookies" do
      cookie = Cookie.new(raw_cookie, httponly: true)
      expect(cookie.to_s).to match(Cookie::HTTPONLY_REGEXP)
    end

    it "flags SameSite cookies" do
      cookie = Cookie.new(raw_cookie, samesite: true)
      expect(cookie.to_s).to match(Cookie::SAMESITE_REGEXP)
    end
  end
end
