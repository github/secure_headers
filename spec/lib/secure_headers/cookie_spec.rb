require 'spec_helper'

module SecureHeaders
  describe Cookie do
    let(:raw_cookie) { "_session=thisisatest" }

    it "does not tamper with cookies when unconfigured" do
      cookie = Cookie.new(raw_cookie, {})
      expect(cookie.to_s).to eq(raw_cookie)
    end

    context "Secure cookies" do
      context "when configured with a boolean" do
        it "flags cookies as Secure" do
          cookie = Cookie.new(raw_cookie, secure: true)
          expect(cookie.to_s).to match(Cookie::SECURE_REGEXP)
        end
      end

      context "when configured with a Hash" do
        it "flags cookies as Secure when whitelisted" do
          cookie = Cookie.new(raw_cookie, secure: { only: ['_session']})
          expect(cookie.to_s).to match(Cookie::SECURE_REGEXP)
        end

        it "does not flag cookies as Secure when excluded" do
          cookie = Cookie.new(raw_cookie, secure: { except: ['_session'] })
          expect(cookie.to_s).not_to match(Cookie::SECURE_REGEXP)
        end
      end
    end

    context "HttpOnly cookies" do
      context "when configured with a boolean" do
        it "flags cookies as HttpOnly" do
          cookie = Cookie.new(raw_cookie, httponly: true)
          expect(cookie.to_s).to match(Cookie::HTTPONLY_REGEXP)
        end
      end

      context "when configured with a Hash" do
        it "flags cookies as HttpOnly when whitelisted" do
          cookie = Cookie.new(raw_cookie, httponly: { only: ['_session']})
          expect(cookie.to_s).to match(Cookie::HTTPONLY_REGEXP)
        end

        it "does not flag cookies as HttpOnly when excluded" do
          cookie = Cookie.new(raw_cookie, httponly: { except: ['_session'] })
          expect(cookie.to_s).not_to match(Cookie::HTTPONLY_REGEXP)
        end
      end
    end

    context "SameSite cookies" do
      context "when configured with a boolean" do
        it "flags cookies as SameSite" do
          cookie = Cookie.new(raw_cookie, samesite: true)
          expect(cookie.to_s).to match(Cookie::SAMESITE_REGEXP)
        end
      end
    end
  end
end
