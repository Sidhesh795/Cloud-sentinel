from backend.security.anomaly import save_model


if __name__ == "__main__":
    path = save_model()
    print(f"Saved anomaly model to {path}")
